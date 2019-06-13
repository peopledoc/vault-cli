import pytest


@pytest.mark.parametrize(
    "path, expected", [("", ["a", "b/"]), ("a", []), ("b", ["c", "d"])]
)
def test_fake_client_list_secrets(vault, path, expected):
    vault.db = {"a": "A", "b/c": "BC", "b/d": "BD"}
    assert vault.list_secrets(path) == expected
