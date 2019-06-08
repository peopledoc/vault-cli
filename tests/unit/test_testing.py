import pytest


@pytest.mark.parametrize(
    "path, expected", [("", ["a", "b/"]), ("a", []), ("b", ["c", "d"])]
)
def test_fake_client_list_secrets(vault, path, expected):
    vault.db = {"a": "A", "b/c": "BC", "b/d": "BD"}
    assert vault.list_secrets(path) == expected


def test_auth_does_nothing(vault):
    vault._init_client()
    vault._authenticate_token()
    vault._authenticate_userpass()
