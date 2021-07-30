import os
import subprocess

import pytest

import vault_cli
from vault_cli import cli


def call(cli_runner, *args, **kwargs):
    call = cli_runner.invoke(cli.cli, *args, **kwargs)
    assert call.exit_code == 0, call.output
    return call


@pytest.fixture
def clean_vault(cli_runner):
    call(cli_runner, ["delete-all", "-f"])
    yield
    call(cli_runner, ["delete-all", "-f"])


def test_integration_cli(cli_runner, clean_vault):

    call(cli_runner, ["set", "a", "value=b"])

    assert call(cli_runner, ["get", "a"]).output == "---\nvalue: b\n"

    assert call(cli_runner, ["get", "a", "--yaml"]).output == "---\nvalue: b\n"

    assert call(cli_runner, ["get", "a", "value"]).output == "b\n"

    assert call(cli_runner, ["get", "a", "value", "--yaml"]).output == "--- b\n...\n"

    call(cli_runner, ["set", "c", "--file=-"], input="{'key1':'val1', 'key2':'val2'}")

    assert call(cli_runner, ["get", "c"]).output == "---\nkey1: val1\nkey2: val2\n"

    # Both testing it and using it to clean the vault
    call(cli_runner, ["delete-all", "--force"])

    assert call(cli_runner, ["list"]).output == "\n"

    call(cli_runner, ["set", "a", "value=b"])

    assert call(cli_runner, ["list"]).output == "a\n"

    call(cli_runner, ["set", "c/d", "foo=e", "bar=f"])

    assert call(cli_runner, ["get", "c/d", "foo"]).output == "e\n"

    assert call(cli_runner, ["list"]).output == "a\nc/\n"

    assert call(cli_runner, ["list", "c"]).output == "d\n"

    assert call(cli_runner, ["get-all", ""]).output == (
        """---
a:
  value: b
c/d:
  bar: f
  foo: e
"""
    )

    assert call(cli_runner, ["get-all", "--no-flat"]).output == (
        """---
a:
  value: b
c:
  d:
    bar: f
    foo: e
"""
    )

    call(cli_runner, ["delete", "a"])

    assert call(cli_runner, ["list"]).output == "c/\n"

    call(cli_runner, ["delete", "c/d", "foo"])

    result = cli_runner.invoke(cli.cli, ["get", "c/d", "foo"])
    assert result.exit_code == 1
    assert (
        result.output
        == """Error: VaultSecretNotFound: Secret not found
Key 'foo' not found in secret at path '/secretkvv1/c/d'
KeyError: 'foo'
"""
    )

    assert call(cli_runner, ["list"]).output == "c/\n"

    call(cli_runner, ["delete-all", "--force"])

    assert call(cli_runner, ["list"]).output == "\n"

    assert call(cli_runner, ["lookup-token"]).output.startswith("---\nauth:")


def test_integration_lib(clean_vault):

    client = vault_cli.get_client()

    client.set_secret("a", {"value": "b"})

    assert client.get_secret("a") == {"value": "b"}

    assert "a" in list(client.delete_all_secrets(""))

    assert client.list_secrets("") == []

    client.set_secret("a", {"value": "b"})

    assert client.list_secrets("") == ["a"]

    client.set_secret("c/d", {"name": "e"})

    assert client.get_secret("c/d") == {"name": "e"}

    assert client.list_secrets("") == ["a", "c/"]

    assert client.list_secrets("c") == ["d"]

    assert client.get_all_secrets("") == {
        "a": {"value": "b"},
        "c": {"d": {"name": "e"}},
    }

    client.delete_secret("a")

    assert client.list_secrets("") == ["c/"]

    assert list(client.delete_all_secrets("")) == ["c/d"]

    assert client.lookup_token()["data"]

    # Use hvac client directly in order to write values that are not in a "value" attribute
    client.client.write(
        client._build_full_path("novalue"), username="name", password="pass"
    )
    assert client.get_secret("novalue") == {"password": "pass", "username": "name"}


def test_env_var_config():
    # Test env var config
    os.environ["VAULT_CLI_TOKEN"] = "some-other-token"
    with pytest.raises(vault_cli.VaultAPIException):
        vault_cli.get_client().set_secret("a", {"name": "value"})


def check_call(command):
    subprocess.check_call(
        command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


@pytest.fixture
def set_ACD(cli_runner, clean_vault):
    call(cli_runner, ["set", "A", "value=B"])
    call(cli_runner, ["set", "C/D", "username=foo", "password=bar"])


def test_boostrap_env(set_ACD):
    env = subprocess.check_output(
        "vault-cli env -p A -p C -p C/D:password=PASS -- env".split()
    )

    assert b"A_VALUE=B\n" in env
    assert b"D_USERNAME=foo\n" in env
    assert b"D_PASSWORD=bar\n" in env
    assert b"PASS=bar\n" in env


def test_ssh(clean_vault, cli_runner):
    # In case this is not sufficienlty explicit that this is a test key, then:
    #
    #        THIS IS A TEST KEY, DO NOT USE IN THE REAL WORLD
    #
    ssh_private = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA/nloeFW
+x5vq/qCi1O8YLAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGRET06x/iK7QVn3
XrQGfNyzTcNB778XBpLv6g2HJ9uEAAAAoEjqItV+JKRilnbsPIrBbxSqL/KgzhEO4iAQBD
WKdaZ6sPyfumXx9RIenITB+trevUI0P8QcMfclwTm6BaXG83i7XjFnywrQFNFpDK+TjlqY
hZiUENBDt6r3dLkt6ozCFT6T0v52X4+art7pReCKqJcQDvMp0y6wqvfkVHWmWPNn9HbfGP
Fh34DrZLZim42czNi6I+ww6+/y68rkmExwToM=
-----END OPENSSH PRIVATE KEY-----
"""
    ssh_public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRET06x/iK7QVn3XrQGfNyzTcNB778XBpLv6g2HJ9uE joachim@pistache"
    ssh_passphrase = "foobar"
    call(
        cli_runner,
        ["set", "ssh_key", f"private={ssh_private}", f"passphrase={ssh_passphrase}"],
    )
    identities = subprocess.run(
        "vault-cli ssh --key ssh_key:private --passphrase ssh_key:passphrase "
        "-- ssh-add -L".split(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert ssh_public in identities.stdout.decode("utf-8")
    assert "Identity added" not in identities.stdout.decode("utf-8")
    assert identities.stderr.decode("utf-8") == ""


@pytest.fixture
def umask():
    current = os.umask(0)
    os.umask(current)
    yield
    os.umask(current)


@pytest.mark.parametrize(
    "flag, expected",
    [
        ("", "0o600"),
        ("--umask=000 ", "0o666"),
    ],
)
def test_umask(set_ACD, umask, tmp_path, flag, expected):
    path = tmp_path / "test_boostrap_env"
    # umask = 0o000 => permissions = 0o666 - 0o000 = 0o666
    subprocess.check_output(f"vault-cli {flag}get A -o {path}".split())
    assert oct(path.stat().st_mode & 0o777) == expected
