import pytest


@pytest.mark.parametrize(
    "path, expected", [("", ["a", "b/"]), ("a", []), ("b", ["c", "d"])]
)
def test_fake_client_list_secrets(vault_cli, path, expected):
    vault_cli.db = {"a": "A", "b/c": "BC", "b/d": "BD"}
    assert vault_cli.list_secrets(path) == expected
