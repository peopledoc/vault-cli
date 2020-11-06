import pytest

from vault_cli import exceptions


def test_vault_overwrite_secret_error():
    assert (
        str(exceptions.VaultOverwriteSecretError(path="yay"))
        == "VaultOverwriteSecretError: Secret at yay already exists"
    )


def test_vault_render_template_error():
    assert str(exceptions.VaultRenderTemplateError("yay")) == "yay"


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
