import yaml
import pytest

from vault_cli import cli
from vault_cli import client


class FakeClient(client.VaultClientBase):
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
        print(kwargs)

    def get_secret(self, path):
        return "bar"

    def list_secrets(self, path):
        return ["foo", "baz"]

    def set_secret(self, path, value):
        self.set = [path, value]

    def delete_secret(self, path):
        self.deleted = path


@pytest.fixture
def backend(mocker):
    backend = FakeClient()
    mocker.patch("vault_cli.requests.RequestsVaultClient",
                 return_value=backend)
    yield backend


def test_bad_backend(cli_runner, backend):
    result = cli_runner.invoke(cli.cli, ["--backend", "bad", "list"])

    assert result.exit_code != 0
    assert "Error: Wrong backend value bad" in result.output


def test_options(cli_runner, mocker):
    func = mocker.patch("vault_cli.client.get_client_from_kwargs")
    result = cli_runner.invoke(cli.cli, [
        "--backend", "requests",
        "--base-path", "bla",
        "--certificate", __file__,
        "--password-file", __file__,
        "--token", "tok",
        "--token-file", __file__,
        "--url", "https://foo",
        "--username", "user",
        "--verify",
        "list"
    ])

    assert result.exit_code == 0
    _, kwargs = func.call_args
    assert set(kwargs) == {
        "backend",
        "base_path",
        "certificate",
        "password_file",
        "token",
        "token_file",
        "url",
        "username",
        "verify",
    }
    assert kwargs["base_path"] == "bla"
    assert kwargs["certificate"].name == __file__
    assert kwargs["password_file"].name == __file__
    assert kwargs["token"] == "tok"
    assert kwargs["token_file"].name == __file__
    assert kwargs["url"] == "https://foo"
    assert kwargs["username"] == "user"
    assert kwargs["verify"] is True


def test_list(cli_runner, backend):
    result = cli_runner.invoke(cli.cli, ["list"])

    assert result.output == "['foo', 'baz']\n"
    assert result.exit_code == 0


def test_get_text(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["get", "a", "--text"])

    assert result.output == "bar\n"
    assert result.exit_code == 0


def test_get_yaml(cli_runner, backend):
    result = cli_runner.invoke(cli.cli, ["get", "a"])

    assert yaml.safe_load(result.output) == "bar"
    assert result.exit_code == 0


def test_get_all(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["get-all", "a"])

    assert yaml.safe_load(result.output) == {'a': {'baz': 'bar', 'foo': 'bar'}}
    assert result.exit_code == 0


def test_set(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b"])

    assert result.exit_code == 0
    assert backend.set == ["a", "b"]


def test_set_list(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b", "c"])

    assert result.exit_code == 0
    assert backend.set == ["a", ["b", "c"]]


def test_set_yaml(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "--yaml", "a", '{"b": "c"}'])

    assert result.exit_code == 0
    assert backend.set == ["a", {"b": "c"}]


def test_delete(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["delete", "a"])

    assert result.exit_code == 0
    assert backend.deleted == "a"


def test_main(mocker, config):
    mock_cli = mocker.patch("vault_cli.cli.cli")
    config.update({"bla": "blu"})

    cli.main()

    mock_cli.assert_called_with(default_map={"bla": "blu"})
