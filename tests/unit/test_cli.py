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

    assert result.output == "---\nvalue: bar\n"
    assert result.exit_code == 0

    result = cli_runner.invoke(cli.cli, ["get", "a", "value"] + extra_args)

    assert result.output == "bar\n"
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "value, output",
    [
        ({"list": [1, 2]}, "---\nlist:\n- 1\n- 2\n"),
        ({"a": "b"}, "---\na: b\n"),
        (None, "null\n"),
    ],
)
def test_get_text_special_cases(cli_runner, vault_with_token, value, output):

    vault_with_token.db = {"a": value}
    result = cli_runner.invoke(cli.cli, ["get", "a"])

    assert result.output == output
    assert result.exit_code == 0


def test_get_yaml(cli_runner, vault_with_token):
    vault_with_token.db = {"a": {"value": "bar"}}
    result = cli_runner.invoke(cli.cli, ["get", "a", "value", "--yaml"])

    assert result.output == "--- bar\n...\n"
    assert result.exit_code == 0


def test_get_all_no_flat(cli_runner, vault_with_token):

    vault_with_token.db = {"a/baz": {"value": "bar"}, "a/foo": {"value": "yay"}}
    result = cli_runner.invoke(cli.cli, ["get-all", "--no-flat", "a"])

    assert yaml.safe_load(result.output) == {
        "a": {"baz": {"value": "bar"}, "foo": {"value": "yay"}}
    }
    assert result.exit_code == 0


def test_get_all_flat(cli_runner, vault_with_token):

    vault_with_token.db = {"a/baz": {"value": "bar"}, "a/foo": {"value": "yay"}}
    result = cli_runner.invoke(cli.cli, ["get-all", "a"])

    assert yaml.safe_load(result.output) == {
        "a/baz": {"value": "bar"},
        "a/foo": {"value": "yay"},
    }
    assert result.exit_code == 0


def test_set(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "attr=b"])

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"attr": "b"}}


def test_set_without_value(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "attr"])

    assert result.exit_code == 2
    assert "Expecting 'key=value' arguments." in result.stdout


def test_set_arg_stdin(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "a", "value=-"], input="yeah")

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "yeah"}}


def test_set_stdin(cli_runner, vault_with_token):
    # Just checking that yaml and stdin are not incompatible
    result = cli_runner.invoke(
        cli.cli, ["set", "--file=-", "a"], input=yaml.safe_dump({"b": "c"})
    )

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"b": "c"}}


def test_set_with_both_prompt_and_stdin(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--prompt", "value", "--file=-", "a"])

    assert result.exit_code != 0
    assert vault_with_token.db == {}


def test_set_with_both_yaml_and_multiple_values(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--yaml", "a", "b", "c"])

    assert result.exit_code != 0
    assert vault_with_token.db == {}


def test_set_prompt(cli_runner, mocker, vault_with_token):

    prompt = mocker.patch("click.prompt")
    prompt.return_value = "b"
    result = cli_runner.invoke(cli.cli, ["set", "--prompt", "a", "value"])
    # test for prompt function
    prompt.assert_called_with(
        "Please enter a value for key `value` of `a`", hide_input=True
    )

    # Correctly stored secret.
    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"value": "b"}}


def test_set_yaml(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set", "--file=-", "a"], input='{"b": "c"}')

    assert result.exit_code == 0
    assert vault_with_token.db == {"a": {"b": "c"}}


@pytest.mark.parametrize(
    "args, expected",
    [
        # no safe-write by default
        (["set", "a", "value=b"], "b"),
        # same, but explicit
        (["--unsafe-write", "set", "a", "value=b"], "b"),
        # safe-write but with force
        (["--safe-write", "set", "--force", "a", "value=b"], "b"),
        # safe-write but the written value is equal to the current value
        (["--safe-write", "set", "a", "value=c"], "c"),
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
        ["--safe-write", "set", "a", "value=b"],
        # no-force
        ["set", "--no-force", "a", "value=b"],
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

    result = cli_runner.invoke(cli.cli, ["set", "a/b/c", "value=d"])

    assert result.exit_code == 1
    assert vault_with_token.db == {"a/b": {"value": "c"}}


def test_set_mix_folders_secrets(cli_runner, vault_with_token):

    vault_with_token.db = {"a/b/c": {"value": "d"}}

    result = cli_runner.invoke(cli.cli, ["set", "a/b", "value=c"])

    assert result.exit_code == 1
    assert vault_with_token.db == {"a/b/c": {"value": "d"}}


def test_set_all(cli_runner, vault_with_token):

    result = cli_runner.invoke(cli.cli, ["set-all"], input="""a/b: {"c": "d"}""")

    assert result.exit_code == 0
    assert result.stdout.strip() == "Done"
    assert vault_with_token.db == {"a/b": {"c": "d"}}


def test_set_all_wrong_type(cli_runner, vault_with_token):
    result = cli_runner.invoke(cli.cli, ["set-all"], input="""[1, 2, 3]""")
    assert result.exit_code != 0
    error = "Error: Mapping expected format is a mapping of paths to secret objects"
    assert result.stdout.strip() == error
    assert vault_with_token.db == {}


def test_set_all_force(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"c": "d"}}
    result = cli_runner.invoke(
        cli.cli, ["set-all", "--no-force"], input="""a/b: {"c": "e"}"""
    )
    assert result.exit_code != 0
    error = (
        "Error: Secret already exists at a/b for key: c\nUse -f to force overwriting"
    )
    assert result.stdout.strip() == error
    assert vault_with_token.db == {"a/b": {"c": "d"}}


def test_set_all_mix(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"c": "d"}}
    result = cli_runner.invoke(cli.cli, ["set-all"], input="""a: {"e": "f"}""")

    assert result.exit_code != 0
    error = "Error: Cannot create a secret at 'a' because it is already a folder containing a/b"
    assert result.stdout.strip() == error
    assert vault_with_token.db == {"a/b": {"c": "d"}}


def test_delete(cli_runner, vault_with_token):

    vault_with_token.db = {"a": {"value": "foo"}, "b": {"value": "bar"}}
    result = cli_runner.invoke(cli.cli, ["delete", "a"])

    assert result.exit_code == 0
    assert vault_with_token.db == {"b": {"value": "bar"}}


def test_env(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"value": "yo"}}
    cli_runner.invoke(cli.cli, ["env", "--envvar", "foo", "--", "echo", "yay"])

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environment"]["FOO_BAR_VALUE"] == "yay"
    assert kwargs["environment"]["FOO_BAZ_VALUE"] == "yo"


def test_env_error(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.forbidden_get_paths.add("foo")

    cli_runner.invoke(cli.cli, ["env", "--envvar", "foo", "--", "echo", "yay"])

    exec_command.assert_not_called()


def test_env_envvar_format_error(cli_runner):
    result = cli_runner.invoke(
        cli.cli, ["env", "--envvar", ":foo", "--", "echo", "yay"]
    )

    assert result.exit_code != 0
    assert "Cannot omit the path if a filter key is provided" in result.output


def test_env_error_force_sub_error(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.forbidden_get_paths.add("foo")

    cli_runner.invoke(
        cli.cli, ["env", "--envvar", "foo", "--force", "--", "echo", "yay"]
    )

    exec_command.assert_called()


def test_env_error_force_main_error(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.forbidden_list_paths.add("foo")

    cli_runner.invoke(
        cli.cli, ["env", "--envvar", "foo", "--force", "--", "echo", "yay"]
    )

    exec_command.assert_called()


def test_env_prefix(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {
        "foo/bar": {"value": "yay"},
        "foo/baz": {"user": "yo", "password": "xxx"},
    }
    cli_runner.invoke(cli.cli, ["env", "--envvar", "foo=prefix", "--", "echo", "yay"])

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environment"]["PREFIX_BAR_VALUE"] == "yay"
    assert kwargs["environment"]["PREFIX_BAZ_USER"] == "yo"
    assert kwargs["environment"]["PREFIX_BAZ_PASSWORD"] == "xxx"


def test_env_filter_key(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {
        "foo/bar": {"value": "yay"},
        "foo/baz": {"user": "yo", "password": "xxx"},
    }
    cli_runner.invoke(
        cli.cli,
        [
            "env",
            "--envvar",
            "foo/baz:user=MYNAME",
            "--envvar",
            "foo/baz:password",
            "--",
            "echo",
            "yay",
        ],
    )

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environment"]["MYNAME"] == "yo"
    assert kwargs["environment"]["PASSWORD"] == "xxx"


def test_env_omit_single_key(cli_runner, vault_with_token, mocker):
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"foo/bar": {"value": "yay"}, "foo/baz": {"password": "yo"}}
    cli_runner.invoke(
        cli.cli, ["env", "--envvar", "foo", "--omit-single-key", "--", "echo", "yay"]
    )

    _, kwargs = exec_command.call_args
    assert kwargs["command"] == ("echo", "yay")
    assert kwargs["environment"]["FOO_BAR"] == "yay"
    assert kwargs["environment"]["FOO_BAZ"] == "yo"


def test_env_file(cli_runner, vault_with_token, mocker, tmp_path):
    mocker.patch("vault_cli.environment.exec_command")

    path = tmp_path / "foo"
    vault_with_token.db = {"foo/bar": {"value": "yay"}}
    cli_runner.invoke(
        cli.cli, ["env", "--file", f"foo/bar:value={path}", "--", "echo", "yay"]
    )
    assert path.read_text() == "yay\n"


def test_env_file_format_error(cli_runner, vault_with_token, mocker, tmp_path):
    mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"foo/bar": {"value": "yay"}}
    result = cli_runner.invoke(
        cli.cli, ["env", "--file", "foo/bar", "--", "echo", "yay"]
    )
    assert result.exit_code != 0
    assert "expects both a vault path and a filesystem path" in result.output


def test_env_file_yaml(cli_runner, vault_with_token, mocker, tmp_path):
    mocker.patch("vault_cli.environment.exec_command")

    path = tmp_path / "foo"
    vault_with_token.db = {"foo/bar": {"value": "yay"}}
    cli_runner.invoke(
        cli.cli,
        ["env", "--file", f"foo/bar={path}", "--", "echo", "yay"],
    )
    assert path.read_text() == "---\nvalue: yay\n"


def test_main(environ, mocker):
    mock_cli = mocker.patch("vault_cli.cli.cli")

    cli.main()

    mock_cli.assert_called_with()
    assert set({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}.items()) <= set(environ.items())


def test_main_askpass(environ, mocker, capsys):
    mock_cli = mocker.patch("vault_cli.cli.cli")
    environ.update({"VAULT_CLI_SSH_PASSPHRASE": "foo"})

    cli.main()

    out = capsys.readouterr().out.strip()
    assert out == "foo"

    mock_cli.assert_not_called()


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

    cli.set_verbosity(1)

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
        {"base_path": "mybase/", "token": "some-token", "verbose": 0, "umask": "0o066"}
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


def test_cp(cli_runner, vault_with_token):
    vault_with_token.db = {
        "a/b": {"value": "c"},
        "d/e": {"value": "f"},
        "d/g": {"value": "h"},
    }

    result = cli_runner.invoke(cli.cli, ["cp", "d", "a"])

    assert result.output.splitlines() == ["Copy 'd/e' to 'a/e'", "Copy 'd/g' to 'a/g'"]
    assert vault_with_token.db == {
        "a/b": {"value": "c"},
        "a/e": {"value": "f"},
        "a/g": {"value": "h"},
        "d/e": {"value": "f"},
        "d/g": {"value": "h"},
    }
    assert result.exit_code == 0


def test_cp_overwrite_safe(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d/b": {"value": "f"}}

    vault_with_token.safe_write = True

    result = cli_runner.invoke(cli.cli, ["cp", "d", "a"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d/b": {"value": "f"}}
    assert result.exit_code != 0


def test_cp_overwrite_force(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d/b": {"value": "f"}}

    result = cli_runner.invoke(cli.cli, ["cp", "d", "a", "--force"])

    assert vault_with_token.db == {"a/b": {"value": "f"}, "d/b": {"value": "f"}}
    assert result.exit_code == 0


def test_cp_mix_folders_secrets(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d": {"value": "e"}}

    result = cli_runner.invoke(cli.cli, ["cp", "d", "a"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d": {"value": "e"}}
    assert result.exit_code != 0


def test_cp_mix_secrets_folders(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}, "d": {"value": "e"}}

    result = cli_runner.invoke(cli.cli, ["cp", "a", "d"])

    assert vault_with_token.db == {"a/b": {"value": "c"}, "d": {"value": "e"}}
    assert result.exit_code != 0


def test_template_from_stdin(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(
        cli.cli, ["template", "-"], input="Hello {{ vault('a/b').value }}"
    )

    assert result.exit_code == 0
    assert result.stdout == "Hello c"


def test_template_from_file(cli_runner, vault_with_token):
    vault_with_token.db = {"a/b": {"value": "c"}}

    with tempfile.NamedTemporaryFile(mode="w+") as fp:
        fp.write("Hello {{ vault('a/b').value }}")
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
                "Hello {{ vault('a/b').value }}\n{% include('"
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
        raise exceptions.VaultException("foo") from ValueError("bar")

    with pytest.raises(click.ClickException) as exc_info:
        inner()

    assert str(exc_info.value) == "VaultException: foo\nValueError: bar"


def test_version(cli_runner):
    result = cli_runner.invoke(cli.cli, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.startswith("vault-cli " + vault_cli.__version__)
    assert result.stdout.endswith("License: Apache Software License\n")


def test_ssh(cli_runner, vault_with_token, mocker):
    ensure = mocker.patch("vault_cli.ssh.ensure_agent")
    add = mocker.patch("vault_cli.ssh.add_key")
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, ["ssh", "--key", "a/b:value", "--", "env"])

    assert result.exit_code == 0
    ensure.assert_called_with()
    add.assert_called_with(key="c", passphrase=None)
    exec_command.assert_called_with(command=("env",))


def test_ssh_passphrase(cli_runner, vault_with_token, mocker):
    ensure = mocker.patch("vault_cli.ssh.ensure_agent")
    add = mocker.patch("vault_cli.ssh.add_key")
    exec_command = mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"a/b": {"value": "c", "passphrase": "d"}}

    result = cli_runner.invoke(
        cli.cli,
        ["ssh", "--key", "a/b:value", "--passphrase", "a/b:passphrase", "--", "env"],
    )

    assert result.exit_code == 0
    ensure.assert_called_with()
    add.assert_called_with(key="c", passphrase="d")
    exec_command.assert_called_with(command=("env",))


def test_ssh_wrong_format_key(cli_runner, vault_with_token, mocker):
    mocker.patch("vault_cli.ssh.ensure_agent")
    mocker.patch("vault_cli.ssh.add_key")
    mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(cli.cli, ["ssh", "--key", "a/b", "--", "env"])

    assert result.exit_code > 0


def test_ssh_wrong_format_passphrase(cli_runner, vault_with_token, mocker):
    mocker.patch("vault_cli.ssh.ensure_agent")
    mocker.patch("vault_cli.ssh.add_key")
    mocker.patch("vault_cli.environment.exec_command")

    vault_with_token.db = {"a/b": {"value": "c"}}

    result = cli_runner.invoke(
        cli.cli,
        ["ssh", "--key", "a/b:value", "--passphrase", "a/b", "--", "env"],
    )

    assert result.exit_code > 0


@pytest.mark.parametrize("input, output", [("022", 0o22), ("0o123", 0o123)])
def test_parse_octal(input, output):
    assert cli.parse_octal(input) == output


@pytest.mark.parametrize(
    "input, output",
    [
        (None, None),
        (0o22, "0o022"),
        (0o123, "0o123"),
        (0o12345, "0o12345"),
        (0, "0o000"),
    ],
)
def test_repr_octal(input, output):
    assert cli.repr_octal(input) == output


def test_ensure_str():
    assert cli.ensure_str("foo", "bar") == "foo"


def test_ensure_str_wrong():
    with pytest.raises(exceptions.VaultWrongType):
        cli.ensure_str(1, "bar")


@pytest.mark.parametrize(
    "input, output",
    [
        ("aa:bb=cc", ("aa", "bb", "cc")),
        ("aa:bb", ("aa", "bb", "")),
        ("aa=cc", ("aa", "", "cc")),
        ("aa", ("aa", "", "")),
        (":bb=cc", ("", "bb", "cc")),
        ("=cc", ("", "", "cc")),
        (":bb", ("", "bb", "")),
        ("", ("", "", "")),
    ],
)
def test_get_env_parts(input, output):
    assert cli.get_env_parts(input) == output
