import pytest

from vault_cli import exceptions, templates


def test_render(vault):

    vault.db = {"a/b": "c"}

    assert templates.render("Hello {{ vault('a/b') }}", client=vault) == "Hello c"


def test_render_path_not_found(vault):
    with pytest.raises(exceptions.VaultSecretNotFound):
        templates.render("Hello {{ vault('a/b') }}", client=vault)
