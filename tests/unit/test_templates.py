import pytest

from vault_cli import exceptions, templates


def test_render(vault_cli):

    vault_cli.db = {"a/b": "c"}

    assert templates.render("Hello {{ vault('a/b') }}", client=vault_cli) == "Hello c"


def test_render_path_not_found(vault_cli):
    with pytest.raises(exceptions.VaultSecretNotFound):
        templates.render("Hello {{ vault('a/b') }}", client=vault_cli)
