import pytest

from vault_cli import exceptions, templates


def test_render(backend):

    backend.db = {"a/b": "c"}

    assert templates.render("Hello {{ vault('a/b') }}", client=backend) == "Hello c"


def test_render_path_not_found(backend):
    with pytest.raises(exceptions.VaultSecretDoesNotExist):
        templates.render("Hello {{ vault('a/b') }}", client=backend)
