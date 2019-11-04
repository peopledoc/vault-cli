import logging
import os
import tempfile

import click
import pytest
import yaml

import vault_cli
from vault_cli import cli, exceptions, settings

# To debug cli_runner.invoke, add the argument "catch_exceptions=False"


def test_options(cli_runner, mocker):
    client = mocker.patch("vault_cli.client.get_client_class").return_value
    mocker.patch(
        "vault_cli.settings.read_file", side_effect=lambda x: "content of {}".format(x)
    )
    result = cli_runner.invoke(
        cli.cli,
        [
            "--base-path",
            "bla",
            "--ca-bundle",
            "yay",
            "--no-render",
            "--login-cert",
            "puc",
            "--login-cert-key",
            "prc",
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
    _, kwargs = client.call_args
    assert set(kwargs) == {
        "base_path",
        "ca_bundle",
        "render",
        "login_cert",
        "login_cert_key",
        "password",
        "safe_write",
        "token",
        "url",
        "username",
        "verify",
    }
    assert kwargs["base_path"] == "bla"
    assert kwargs["ca_bundle"] == "yay"
    assert kwargs["login_cert"] == "puc"
    assert kwargs["login_cert_key"] == "prc"
    assert kwargs["password"] == "content of b"
    assert kwargs["token"] == "content of c"
    assert kwargs["url"] == "https://foo"
    assert kwargs["username"] == "user"
    assert kwargs["verify"] is True
    assert kwargs["render"] is False


@pytest.fixture
def vault_with_token(vault):
    vault.token = "token"
    vault.freeze_settings = True
    return vault


def test_list(cli_runner, vault_with_token):
    vault_with_token.db = {"foo": {"value": "yay"}, "baz": {"value": "ho"}}
    result = cli_runner.invoke(cli.cli, ["list"])

    assert result.output == "baz\nfoo\n"
    assert result.exit_code == 0


@pytest.mark.parametrize("extra_args", [["--text"], []])
def test_get_text(cli_runner, vault_with_token, extra_args):

    vault_with_token.db = {"a": {"value": "bar"}}
    result = cli_runner.invoke(cli.cli, ["get", "a"] + extra_args)

    assert result.output == "bar\n"
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "input, output",
    [([1, 2], "---\n- 1\n- 2\n"), ({"a": "b"}, "---\na: b\n"), (None, "null\n")],
)
def test_get_text_special_cases(cli_runner, vault_with_token, input, output):

    vault_with_token.db = {"a": {"value": input}}
    result = cli_runner.invoke(cli.cli, ["get", "a"])

    assert result.output == output
    assert result.exit_code == 0


def test_get_yaml(cli_runner, vault_with_token):
    vault_with_token.db = {"a": {"value": "bar"}}
    result = cli_runner.invoke(cli.cli, ["get", "a", "--yaml"])

    assert result.output == "--- bar\n...\n"
    assert result.exit_code == 0


def test_get_all(cli_runner, vault_with_token):

    vault_with_token.db = {"a/baz": {"value": "bar"}, "a/foo": {"value": "yay"}}
    result = cli_runner.invoke(cli.cli, ["get-all", "a"])

    assert yaml.safe_load(result.output) == {"a": {"baz": "bar", "foo": "yay"}}
    assert result.exit_code == 0


def test_get_all_flat(cli_runner, vault_with_token):

    vault_with_token.db = {"a/baz": {"value": "bar"}, "a/foo": {"value": "yay"}}
    result = cli_runner.invoke(cli.cli, ["get-all", "--flat", "a"])

    assert yaml.safe_load(result.output) == {"a/baz": "bar", "a/foo": "yay"}
    assert result.exit_code == 0


def test_set(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b"])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "b"}}


def test_set_arg_stdin(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--stdin", "a", "b"])

    assert result.exit_code != 0


def test_set_stdin(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--stdin", "a"], input="b")

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "b"}}


def test_set_stdin_yaml(cli_runner, vault_with_token):
    # Just checking that yaml and stdin are not incompatible
    result = cli_runner.invoke(
        cli.cli, ["set", "--stdin", "--yaml", "a"], input=yaml.safe_dump({"b": "c"})
    )

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": {"b": "c"}}}


def test_set_with_both_prompt_and_value(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--prompt", "a", "b"])

    assert result.exit_code != 0
    assert vault_with_token.db == {}


def test_set_with_both_prompt_and_stdin(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--prompt", "--stdin", "a"])

    assert result.exit_code != 0
    assert vault_with_token.db == {}


def test_set_with_both_yaml_and_multiple_values(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--yaml", "a", "b", "c"])

    assert result.exit_code != 0
    assert vault_with_token.db == {}


def test_set_strip(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "  b  "])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "b"}}


def test_set_no_strip(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--no-strip", "a", "  b  "])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "  b  "}}


def test_set_prompt(cli_runner, mocker, vault_with_token):

    prompt = mocker.patch("click.prompt")
    prompt.return_value = "b"
    result = cli_runner.invoke(cli.cli, ["set", "--prompt", "a"])
    # test for prompt function
    prompt.assert_called_with("Please enter value for `a`", hide_input=True)

    # Correctly stored secret.
    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "b"}}


def test_set_list(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "b", "c"])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": ["b", "c"]}}


def test_set_yaml(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--yaml", "a", '{"b": "c"}'])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": {"b": "c"}}}


@pytest.mark.parametrize(
    "args, expected",
    [
        # no safe-write by default
        (["set", "a", "b"], "b"),
        # same, but explicit
        (["--unsafe-write", "set", "a", "b"], "b"),
        # safe-write but with force
        (["--safe-write", "set", "--force", "a", "b"], "b"),
        # safe-write but the written value is equal to the current value
        (["--safe-write", "set", "a", "c"], "c"),
    ],
)
def test_set_overwrite_valid(cli_runner, vault_with_token, args, expected):

    vault_with_token.db = {"a": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, args)

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": expected}}


@pytest.mark.parametrize(
    "args",
    [
        # safe-write
        ["--safe-write", "set", "a", "b"],
        # no-force
        ["set", "--no-force", "a", "b"],
    ],
)
def test_set_overwrite_safe_invalid(cli_runner, vault_with_token, args):

    vault_with_token.safe_write = "--safe-write" in args
    vault_with_token.db = {"a": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, args)

    assert result.exit_code == 1
    assert vault_with_token.db == {"a": {"value": "c"}}


def test_set_mix_secrets_folders(cli_runner, vault_with_token):

    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, ["set", "a/b/c", "d"])

    assert result.exit_code == 1
    assert vault_with_token.db == {"a/b": {"value": "c"}}


def test_set_mix_folders_secrets(cli_runner, vault_with_token):

    vault_with_token.db = {"a/b/c": {"value": "d"}}

    result = cli_runner.invoke(cli.cli, ["set", "a/b", "c"])

    assert result.exit_code == 1
    assert vault_with_token.db == {"a/b/c": {"value": "d"}}


def test_delete(cli_runner, vault_with_token):

    vault_with_token.db = {"a": {"value": "foo"}, "b": {"value": "bar"}}
    result = cli_runner.invoke(cli.cli, ["delete", "a"])

    assert result.exit_code == 0
    assert vault_with_token.db == {"b": {"value": "bar"}}


def test_env(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}
    cli_runner.invoke(cli.cli, ["env", "--path", "foo", "--", "echo", "yay"])

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environ"]["FOO_BAR"] == "yay"
    assert kwargs["environ"]["FOO_BAZ"] == "yo"


def test_env_prefix(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}
    cli_runner.invoke(cli.cli, ["env", "--path", "foo=prefix", "--", "echo", "yay"])

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environ"]["PREFIX_BAR"] == "yay"
    assert kwargs["environ"]["PREFIX_BAZ"] == "yo"


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
    [("bla", ["bla"]), (None, ["./vault.yml", "~/.vault.yml", "/etc/vault.yml"])],
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
        # Relevant keys is copied from second dict
        ({}, {"VAULT_CLI_PASSWORD": "h"}, {"password": "h"}),
        ({}, {"VAULT_CLI_TOKEN": "i"}, {"token": "i"}),
        # Second dict has priority
        ({"password": "l"}, {"VAULT_CLI_PASSWORD": "m"}, {"password": "m"}),
        ({"token": "n"}, {"VAULT_CLI_TOKEN": "o"}, {"token": "o"}),
    ],
)
def test_extract_special_args(config, environ, expected):
    result = cli.extract_special_args(config, environ)

    assert set(result) == {"password", "token"}
    # remove None
    result = {key: value for key, value in result.items() if value is not None}

    assert result == expected


def test_set_verbosity(mocker):
    basic_config = mocker.patch("logging.basicConfig")

    cli.set_verbosity(None, None, 1)

    basic_config.assert_called_with(level=logging.INFO)


def test_dump_config(cli_runner):
    result = cli_runner.invoke(
        cli.cli,
        [
            "--config-file=/dev/null",
            "--base-path=mybase/",
            "--token-file=-",
            "dump-config",
        ],
        input="some-token",
    )

    expected_settings = settings.DEFAULTS._as_dict()
    expected_settings.update(
        {"base_path": "mybase/", "token": "some-token", "verbose": 0}
    )

    output = yaml.safe_load(result.output)

    assert output == expected_settings


def test_delete_all(cli_runner, vault_with_token):
    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}

    result = cli_runner.invoke(cli.cli, ["delete-all"], input="y\ny")

    assert result.output.splitlines() == [
        "Delete 'foo/bar'? [y/N]: y",
        "Deleted 'foo/bar'",
        "Delete 'foo/baz'? [y/N]: y",
        "Deleted 'foo/baz'",
    ]
    assert vault_with_token.db == {}
    assert result.exit_code == 0


def test_delete_all_cancel(cli_runner, vault_with_token):
    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}

    result = cli_runner.invoke(cli.cli, ["delete-all"], input="y\nn")

    assert result.output.splitlines() == [
        "Delete 'foo/bar'? [y/N]: y",
        "Deleted 'foo/bar'",
        "Delete 'foo/baz'? [y/N]: n",
        "Aborted!",
    ]
    assert vault_with_token.db == {"foo/baz": {"value": "yo"}}
    assert result.exit_code != 0


def test_delete_all_force(cli_runner, vault_with_token):
    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}

    result = cli_runner.invoke(cli.cli, ["delete-all", "--force"])

    assert result.output.splitlines() == ["Deleted 'foo/bar'", "Deleted 'foo/baz'"]
    assert vault_with_token.db == {}
    assert result.exit_code == 0


def test_mv(cli_runner, vault_with_token):
    vault_with_token.db = {
        "a/b": {"value": "c"},
        "d/e": {"value": "f"},
        "d/g": {"value": "h"},
    }

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert result.output.splitlines() == ["Move 'd/e' to 'a/e'", "Move 'd/g' to 'a/g'"]
    assert vault_with_token.db == {
        "a/b": {"value": "c"},
        "a/e": {"value": "f"},
        "a/g": {"value": "h"},
    }
    assert result.exit_code == 0


def test_mv_overwrite_safe(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d/b": {"value": "f"}}

    vault_with_token.safe_write = True

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d/b": {"value": "f"}}
    assert result.exit_code != 0


def test_mv_overwrite_force(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d/b": {"value": "f"}}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a", "--force"])

    assert vault_with_token.db == {"a/b": {"value": "f"}}
    assert result.exit_code == 0


def test_mv_mix_folders_secrets(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d": {"value": "e"}}

    result = cli_runner.invoke(cli.cli, ["mv", "d", "a"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d": {"value": "e"}}
    assert result.exit_code != 0


def test_mv_mix_secrets_folders(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d": {"value": "e"}}

    result = cli_runner.invoke(cli.cli, ["mv", "a", "d"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d": {"value": "e"}}
    assert result.exit_code != 0


def test_template_from_stdin(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(
        cli.cli, ["template", "-"], input="Hello {{ vault('a/b') }}"
    )

    assert result.exit_code == 0
    assert result.stdout == "Hello c"


def test_template_from_file(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    with tempfile.NamedTemporaryFile(mode="w+") as fp:
        fp.write("Hello {{ vault('a/b') }}")
        fp.flush()
        result = cli_runner.invoke(
            cli.cli, ["template", fp.name], catch_exceptions=False
        )

    assert result.exit_code == 0
    assert result.stdout == "Hello c"


def test_template_from_file_with_include(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    with tempfile.NamedTemporaryFile(dir=os.getcwd(), mode="w+") as template_file:
        with tempfile.NamedTemporaryFile(dir=os.getcwd(), mode="w+") as include_file:
            template_file.write(
                "Hello {{ vault('a/b') }}\n{% include('"
                + os.path.basename(include_file.name)
                + "') %}"
            )
            template_file.flush()
            include_file.write("Hello all")
            include_file.flush()

            result = cli_runner.invoke(
                cli.cli, ["template", template_file.name], catch_exceptions=False
            )

    assert result.exit_code == 0
    assert result.stdout == "Hello c\nHello all"


def test_lookup_token(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, ["lookup-token"])

    assert result.exit_code == 0
    assert yaml.safe_load(result.stdout)["data"]["expire_time"].startswith(
        "2100-01-01T00:00:00"
    )


def test_handle_errors(cli_runner):
    @cli.handle_errors()
    def inner():
        raise exceptions.VaultException("yay")

    with pytest.raises(click.ClickException):
        inner()


def test_version(cli_runner):
    result = cli_runner.invoke(cli.cli, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.startswith("vault-cli " + vault_cli.__version__)
    assert result.stdout.endswith("License: Apache Software License\n")


@pytest.mark.parametrize(
    "input, output",
    [
        ("hey", "hey"),
        ("hey ", "hey"),
        ("hey ho ", "hey ho"),
        ("hey ho\n", "hey ho"),
        ("hey\nho", "hey\nho\n"),
        ("hey\nho ", "hey\nho\n"),
        ("hey\nho\n", "hey\nho\n"),
    ],
)
def test_fix_whitespaces(input, output):
    assert cli.fix_whitespaces(input) == output
