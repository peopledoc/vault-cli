import os

import pytest

import vault_cli
from vault_cli import cli


def call(cli_runner, *args):
    call = cli_runner.invoke(cli.cli, *args)
    assert call.exit_code == 0, call.output
    return call


def test_integration_cli(cli_runner):
    call(cli_runner, ["set", "a", "b"])

    assert call(cli_runner, ["get", "a", "--text"]).output == "b\n"

    assert call(cli_runner, ["list"]).output == "a\n"

    call(cli_runner, ["set", "c/d", "e"])

    assert call(cli_runner, ["get", "c/d"]).output == "--- e\n...\n"

    assert call(cli_runner, ["list"]).output == "a\nc/\n"

    assert call(cli_runner, ["list", "c"]).output == "d\n"

    assert call(cli_runner, ["get-all", ""]).output == (
        """---
a: b
c:
  d: e
"""
    )

    call(cli_runner, ["delete", "a"])

    assert call(cli_runner, ["list"]).output == "c/\n"

    call(cli_runner, ["delete", "c/d"])


def test_integration_lib():

    client = vault_cli.get_client()

    client.set_secret("a", "b")

    assert client.get_secret("a") == "b"

    assert client.list_secrets("") == ["a"]

    client.set_secret("c/d", "e")

    assert client.get_secret("c/d") == "e"

    assert client.list_secrets("") == ["a", "c/"]

    assert client.list_secrets("c") == ["d"]

    assert client.get_all([""]) == {"a": "b", "c": {"d": "e"}}

    client.delete_secret("a")

    assert client.list_secrets("") == ["c/"]

    client.delete_secret("c/d")


def test_env_var_config():
    # Test env var config
    os.environ["VAULT_CLI_TOKEN"] = "some-other-token"
    with pytest.raises(vault_cli.VaultAPIException):
        vault_cli.get_client().set_secret("a", "b")
