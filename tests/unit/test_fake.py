import pytest


@pytest.mark.parametrize(
    "path, expected", [("", ["a", "b/"]), ("a", []), ("b", ["c", "d"])]
)
def test_fake_client_list_secrets(backend, path, expected):
    backend.db = {"a": "A", "b/c": "BC", "b/d": "BD"}
    assert backend.list_secrets(path) == expected
