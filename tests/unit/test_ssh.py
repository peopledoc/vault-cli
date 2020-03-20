import pytest

from vault_cli import ssh


@pytest.fixture
def exec(mocker):
    return mocker.patch("vault_cli.environment.exec_command")


def test_ensure_agent(exec, environ):
    ssh.ensure_agent()
    exec.assert_called()
    _, kw = exec.call_args
    assert kw["command"][0] == "ssh-agent"


def test_ensure_agent_already_present(exec, environ):
    environ["SSH_AUTH_SOCK"] = "foo"
    ssh.ensure_agent()
    exec.assert_not_called()


# This should rather be an integration test
def test_launch_command(environ):
    environ.update({"A": "B"})
    stdout = ssh._launch_command(["env"], "", {"C": "D"})
    assert "A=B\nC=D" in stdout


@pytest.fixture
def launch_command(mocker):
    return mocker.patch("vault_cli.ssh._launch_command")


def test_add_key(launch_command, environ):
    ssh.add_key(key="foo")
    launch_command.assert_called_with(["ssh-add", "-"], environment={}, stdin="foo")


def test_add_key_password(launch_command, environ, mocker):
    ssh.add_key(key="foo", passphrase="bar")
    launch_command.assert_called_with(
        ["ssh-add", "-"],
        environment={
            "VAULT_CLI_SSH_PASSPHRASE": "bar",
            "SSH_ASKPASS": mocker.ANY,
            "DISPLAY": ":0",
        },
        stdin="foo",
    )
