import logging

import click
import pytest
import yaml

from vault_cli import cli, exceptions, settings


def test_bad_backend(cli_runner, backend):
    result = cli_runner.invoke(cli.cli, ["--backend", "bad", "list"])

    assert result.exit_code != 0
    assert "Error: Wrong backend value bad" in result.output


def test_options(cli_runner, mocker):
    func = mocker.patch("vault_cli.client.get_client_from_kwargs")
    mocker.patch(
        "vault_cli.settings.read_file", side_effect=lambda x: "content of {}".format(x)
    )
    result = cli_runner.invoke(
        cli.cli,
        [
            "--backend",
            "requests",
            "--base-path",
            "bla",
            "--ca-bundle",
            "yay",
            "--certificate-file",
            "a",
            "--password-file",
            "b",
            "--token-file",
            "c",
            "--url",
            "https://foo",
            "--username",
            "user",
            "--verify",
            "list",
        ],
    )

    assert result.exit_code == 0, result.output
    _, kwargs = func.call_args
    assert set(kwargs) == {
        "backend",
        "base_path",
        "ca_bundle",
        "certificate",
        "password",
        "token",
        "url",
        "username",
        "verify",
    }
    assert kwargs["base_path"] == "bla"
    assert kwargs["ca_bundle"] == "yay"
    assert kwargs["certificate"] == "content of a"
    assert kwargs["password"] == "content of b"
    assert kwargs["token"] == "content of c"
    assert kwargs["url"] == "https://foo"
    assert kwargs["username"] == "user"
    assert kwargs["verify"] is True


def test_list(cli_runner, backend):
    backend.db = {"foo": "yay", "baz": "ho"}
    result = cli_runner.invoke(cli.cli, ["list"])

    assert result.output == "baz\nfoo\n"
    assert result.exit_code == 0


def test_get_text(cli_runner, backend):

    backend.db = {"a": "bar"}
    result = cli_runner.invoke(cli.cli, ["get", "a", "--text"])

    assert result.output == "bar\n"
    assert result.exit_code == 0


def test_get_yaml(cli_runner, backend):
    backend.db = {"a": "bar"}
    result = cli_runner.invoke(cli.cli, ["get", "a"])

    assert yaml.safe_load(result.output) == "bar"
    assert result.exit_code == 0


def test_get_all(cli_runner, backend):

    backend.db = {"a/baz": "bar", "a/foo": "yay"}
    result = cli_runner.invoke(cli.cli, ["get-all", "a"])

    print(result.output)
    assert yaml.safe_load(result.output) == {"a": {"baz": "bar", "foo": "yay"}}
    assert result.exit_code == 0


def test_set(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b"])

    assert result.exit_code == 0
    assert backend.db == {"a": "b"}


def test_set_arg_stdin(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "--stdin", "a", "b"])

    assert result.exit_code != 0


def test_set_stdin(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "--stdin", "a"], input="b")

    assert result.exit_code == 0
    assert backend.db == {"a": "b"}


def test_set_stdin_yaml(cli_runner, backend):
    # Just checking that yaml and stdin are not incompatible
    result = cli_runner.invoke(
        cli.cli, ["set", "--stdin", "--yaml", "a"], input=yaml.safe_dump({"b": "c"})
    )

    assert result.exit_code == 0
    assert backend.db == {"a": {"b": "c"}}


def test_set_list(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b", "c"])

    assert result.exit_code == 0
    assert backend.db == {"a": ["b", "c"]}


def test_set_yaml(cli_runner, backend):

    result = cli_runner.invoke(cli.cli, ["set", "--yaml", "a", '{"b": "c"}'])

    assert result.exit_code == 0
    assert backend.db == {"a": {"b": "c"}}


def test_set_overwrite(cli_runner, backend):

    backend.db = {"a": "c"}

    result = cli_runner.invoke(cli.cli, ["set", "a", "b"])

    assert result.exit_code == 1
    assert backend.db == {"a": "c"}


def test_set_overwrite_force(cli_runner, backend):

    backend.db = {"a": "c"}

    result = cli_runner.invoke(cli.cli, ["set", "a", "b", "--force"])

    assert result.exit_code == 0
    assert backend.db == {"a": "b"}


def test_set_mix_secrets_folders(cli_runner, backend):

    backend.db = {"a/b": "c"}

    result = cli_runner.invoke(cli.cli, ["set", "a/b/c", "d"])

    assert result.exit_code == 1
    assert backend.db == {"a/b": "c"}


def test_set_mix_folders_secrets(cli_runner, backend):

    backend.db = {"a/b/c": "d"}

    result = cli_runner.invoke(cli.cli, ["set", "a/b", "c"])

    assert result.exit_code == 1
    assert backend.db == {"a/b/c": "d"}


def test_delete(cli_runner, backend):

    backend.db = {"a": "foo", "b": "bar"}
    result = cli_runner.invoke(cli.cli, ["delete", "a"])

    assert result.exit_code == 0
    assert backend.db == {"b": "bar"}


def test_env(cli_runner, backend, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    backend.db = {"foo/bar": "yay", "foo/baz": "yo"}
    cli_runner.invoke(
        cli.cli, ["env", "--path", "foo", "--", "echo", "yay"], catch_exceptions=False
    )

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environ"]["FOO_BAR"] == "yay"
    assert kwargs["environ"]["FOO_BAZ"] == "yo"


def test_main(mocker):
    mock_cli = mocker.patch("vault_cli.cli.cli")
    environ = mocker.patch("os.environ", {})

    cli.main()

    mock_cli.assert_called_with()
    assert environ == {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}


def test_load_config_no_config(mocker):
    ctx = mocker.Mock()
    cli.load_config(ctx, None, "no")

    assert ctx.default_map == {}


@pytest.mark.parametrize(
    "value, expected",
    [("bla", ["bla"]), (None, ["./.vault.yml", "~/.vault.yml", "/etc/vault.yml"])],
)
def test_load_config(mocker, value, expected):
    ctx = mocker.Mock()
    build = mocker.patch(
        "vault_cli.settings.build_config_from_files", return_value={"a": "b"}
    )
    cli.load_config(ctx, None, value)

    assert ctx.default_map == {"a": "b"}
    build.assert_called_with(*expected)


@pytest.mark.parametrize(
    "config, environ, expected",
    [
        # Empty does not crash or what
        ({}, {}, {}),
        # Irrelevant keys are not copied over
        ({"a": "b"}, {"c", "d"}, {}),
        # Relevant keys is copied from first dict
        ({"password": "e"}, {}, {"password": "e"}),
        ({"token": "f"}, {}, {"token": "f"}),
        ({"certificate": "g"}, {}, {"certificate": "g"}),
        # Relevant keys is copied from second dict
        ({}, {"VAULT_CLI_PASSWORD": "h"}, {"password": "h"}),
        ({}, {"VAULT_CLI_TOKEN": "i"}, {"token": "i"}),
        ({}, {"VAULT_CLI_CERTIFICATE": "j"}, {"certificate": "j"}),
        # Second dict has priority
        ({"password": "l"}, {"VAULT_CLI_PASSWORD": "m"}, {"password": "m"}),
        ({"token": "n"}, {"VAULT_CLI_TOKEN": "o"}, {"token": "o"}),
        ({"certificate": "p"}, {"VAULT_CLI_CERTIFICATE": "q"}, {"certificate": "q"}),
        # Both dict are used
        (
            {"password": "r"},
            {"VAULT_CLI_CERTIFICATE": "s"},
            {"password": "r", "certificate": "s"},
        ),
    ],
)
def test_extract_special_args(config, environ, expected):
    result = cli.extract_special_args(config, environ)

    assert set(result) == {"password", "token", "certificate"}
    # remove None
    result = {key: value for key, value in result.items() if value is not None}

    assert result == expected


def test_set_verbosity(mocker):
    basic_config = mocker.patch("logging.basicConfig")

    cli.set_verbosity(None, None, 1)

    basic_config.assert_called_with(level=logging.INFO)


def test_dump_config(cli_runner, backend):
    result = cli_runner.invoke(
        cli.cli,
        ["--base-path", "mybase/", "--token-file", "-", "dump-config"],
        input="some-token",
    )

    expected_settings = settings.DEFAULTS.copy()
    expected_settings.update(
        {"base_path": "mybase/", "token": "some-token", "verbose": 0}
    )

    output = yaml.safe_load(result.output)

    assert output == expected_settings


def test_delete_all(cli_runner, backend):
    backend.db = {"foo/bar": "yay", "foo/baz": "yo"}

    result = cli_runner.invoke(cli.cli, ["delete-all"], input="y\ny")

    assert result.output.splitlines() == [
        "Delete 'foo/bar'? [y/N]: y",
        "Deleted 'foo/bar'",
        "Delete 'foo/baz'? [y/N]: y",
        "Deleted 'foo/baz'",
    ]
    assert backend.db == {}
    assert result.exit_code == 0


def test_delete_all_cancel(cli_runner, backend):
    backend.db = {"foo/bar": "yay", "foo/baz": "yo"}

    result = cli_runner.invoke(cli.cli, ["delete-all"], input="y\nn")

    assert result.output.splitlines() == [
        "Delete 'foo/bar'? [y/N]: y",
        "Deleted 'foo/bar'",
        "Delete 'foo/baz'? [y/N]: n",
        "Aborted!",
    ]
    assert backend.db == {"foo/baz": "yo"}
    assert result.exit_code != 0


def test_delete_all_force(cli_runner, backend):
    backend.db = {"foo/bar": "yay", "foo/baz": "yo"}

    result = cli_runner.invoke(cli.cli, ["delete-all", "--force"])

    assert result.output.splitlines() == ["Deleted 'foo/bar'", "Deleted 'foo/baz'"]
    assert backend.db == {}
    assert result.exit_code == 0


def test_mv(cli_runner, backend):
    backend.db = {"a/b": "c", "d/e": "f", "d/g": "h"}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert result.output.splitlines() == ["Move 'd/e' to 'a/e'", "Move 'd/g' to 'a/g'"]
    assert backend.db == {"a/b": "c", "a/e": "f", "a/g": "h"}
    assert result.exit_code == 0


def test_mv_overwrite(cli_runner, backend):
    backend.db = {"a/b": "c", "d/b": "f"}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert backend.db == {"a/b": "c", "d/b": "f"}
    assert result.exit_code != 0


def test_mv_overwrite_force(cli_runner, backend):
    backend.db = {"a/b": "c", "d/b": "f"}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a", "--force"])

    assert backend.db == {"a/b": "f"}
    assert result.exit_code == 0


def test_mv_mix_folders_secrets(cli_runner, backend):
    backend.db = {"a/b": "c", "d": "e"}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert backend.db == {"a/b": "c", "d": "e"}
    assert result.exit_code != 0


def test_mv_mix_secrets_folders(cli_runner, backend):
    backend.db = {"a/b": "c", "d": "e"}

    result = cli_runner.invoke(cli.cli, ["mv", "a", "d"])

    assert backend.db == {"a/b": "c", "d": "e"}
    assert result.exit_code != 0


def test_template(cli_runner, backend):
    backend.db = {"a/b": "c"}

    result = cli_runner.invoke(
        cli.cli, ["template", "-"], input="Hello {{ vault('a/b') }}"
    )

    assert result.exit_code == 0
    assert result.stdout == "Hello c"


def test_handle_errors(cli_runner):
    @cli.handle_errors()
    def inner():
        raise exceptions.VaultException("yay")

    with pytest.raises(click.ClickException):
        inner()
