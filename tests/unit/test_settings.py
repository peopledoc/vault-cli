from __future__ import unicode_literals

import io
import logging

import pytest

from vault_cli import exceptions, settings


def test_read_config_file_not_existing():
    assert settings.read_config_file("/non-existant-file") is None


def test_read_config_file_other_error():
    assert settings.read_config_file("/") is None


def test_read_config_file(tmpdir):
    path = str(tmpdir.join("test.yml"))
    open(path, "w").write('{"yay": 1}')

    assert settings.read_config_file(path) == {"yay": 1}


def test_dash_to_underscores():
    result = settings.dash_to_underscores({"a": "b", "c_d": "e_f", "g-h": "i-j"})
    expected = {"a": "b", "c_d": "e_f", "g_h": "i-j"}
    assert result == expected


def test_read_all_files_no_file():
    d = {"token": "yay", "certificate": "yo", "password": "aaa"}
    assert settings.read_all_files(d) == d


def test_read_all_files(tmpdir):
    token_path = str(tmpdir.join("token"))
    open(token_path, "wb").write(b"yay")
    certificate_path = str(tmpdir.join("certificate"))
    open(certificate_path, "wb").write(b"yo")
    password_path = str(tmpdir.join("password"))
    open(password_path, "wb").write(b"aaa")

    d = {
        "token_file": token_path,
        "certificate_file": certificate_path,
        "password_file": password_path,
    }
    expected = {"token": "yay", "certificate": "yo", "password": "aaa"}
    assert settings.read_all_files(d) == expected


def test_read_file_stdin(mocker):
    mocker.patch("sys.stdin", io.StringIO("yay"))
    assert settings.read_file("-") == "yay"


def test_build_config_from_files(mocker):
    settings.build_config_from_files.cache_clear()
    config_file = {"test-a": "b"}
    mocker.patch("vault_cli.settings.read_config_file", return_value=config_file)
    read_all_files = mocker.patch(
        "vault_cli.settings.read_all_files", side_effect=lambda x: x
    )

    result = settings.build_config_from_files("a")

    assert result["test_a"] == "b"
    assert "url" in result
    assert read_all_files.called is True


def test_build_config_from_files_no_files(mocker):
    settings.build_config_from_files.cache_clear()
    mocker.patch("vault_cli.settings.read_config_file", return_value=None)

    result = settings.build_config_from_files("a")

    assert result == settings.DEFAULTS


def test_get_vault_options(mocker):
    mocker.patch("vault_cli.settings.build_config_from_files", return_value={"a": "b"})
    mocker.patch("os.environ", {"VAULT_CLI_URL": "d"})

    expected = {"a": "b", "url": "d", "e": "f"}

    assert settings.get_vault_options(e="f") == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("true", True),
        ("True", True),
        ("True", True),
        ("t", True),
        ("T", True),
        ("1", True),
        ("yes", True),
        ("YES", True),
        ("y", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("f", False),
        ("F", False),
        ("0", False),
        ("no", False),
        ("NO", False),
        ("n", False),
        ("N", False),
    ],
)
def test_load_bool(value, expected):
    assert settings.load_bool(value) == expected


def test_load_bool_wrong():
    with pytest.raises(exceptions.VaultSettingsError):
        assert settings.load_bool("wrong")


@pytest.mark.parametrize(
    "value, expected",
    [
        ({"COIN": "yay"}, {}),
        ({"VAULT_CLI_BLA": "yay"}, {}),
        ({"VAULT_CLI_URL": "yay"}, {"url": "yay"}),
        ({"VAULT_CLI_BASE_PATH": "yay"}, {"base_path": "yay"}),
        ({"VAULT_CLI_VERIFY": "t"}, {"verify": True}),
        (
            {"VAULT_CLI_VERIFY": "t", "VAULT_CLI_BASE_PATH": "yay"},
            {"verify": True, "base_path": "yay"},
        ),
    ],
)
def test_build_config_from_env(value, expected):
    assert settings.build_config_from_env(value) == expected


@pytest.mark.parametrize(
    "verbosity, log_level",
    [(0, "WARNING"), (1, "INFO"), (2, "DEBUG"), (3, "DEBUG"), (None, "WARNING")],
)
def get_log_level(verbosity, log_level):
    assert settings.get_log_level(verbosity=verbosity) == getattr(logging, log_level)
