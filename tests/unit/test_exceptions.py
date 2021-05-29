import pytest

from vault_cli import exceptions


@pytest.mark.parametrize(
    "kwargs, out",
    [
        ({"path": "yay"}, "Secret already exists at yay"),
        ({"path": "yay", "keys": ["a"]}, "Secret already exists at yay for key: a"),
        (
            {"path": "yay", "keys": ["a", "b"]},
            "Secret already exists at yay for keys: a, b",
        ),
    ],
)
def test_vault_overwrite_secret_error(kwargs, out):
    assert str(exceptions.VaultOverwriteSecretError(**kwargs)) == out


@pytest.mark.parametrize(
    "errors, expected",
    [
        (None, """Unexpected vault error"""),
        (["damn", "gosh"], """Unexpected vault error\ndamn\ngosh"""),
    ],
)
def test_vault_api_exception(errors, expected):
    exc_str = str(exceptions.VaultAPIException(errors=errors))

    assert exc_str == expected
