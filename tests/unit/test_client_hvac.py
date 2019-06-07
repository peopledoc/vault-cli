import json

import hvac
import pytest

from vault_cli import client, exceptions


"""
In this module, we only check that we call hvac the way we meant to.
Testing that we work correctly with hvac as a whole is done in the integration
test.
"""


def get_client(**additional_kwargs):
    kwargs = {
        "url": "http://vault:8000",
        "verify": True,
        "base_path": "bla",
        "certificate": None,
        "token": "tok",
        "username": None,
        "password": None,
        "ca_bundle": None,
    }
    kwargs.update(additional_kwargs)
    return client.get_client(**kwargs)


@pytest.fixture
def mock_hvac(mocker):
    yield mocker.patch("hvac.Client").return_value


def test_token(mock_hvac):
    get_client()

    assert mock_hvac.token == "tok"


def test_userpass(mock_hvac):

    get_client(token=None, username="myuser", password="pass")

    mock_hvac.auth_userpass.assert_called_with("myuser", "pass")


def test_get_secret(mock_hvac):

    mock_hvac.read.return_value = {"data": {"value": "b"}}

    assert get_client().get_secret("a") == "b"

    mock_hvac.read.assert_called_with("bla/a")


def test_get_secret_not_found(mock_hvac):

    mock_hvac.read.return_value = None

    with pytest.raises(exceptions.VaultAPIException):
        assert get_client().get_secret("a")

    mock_hvac.read.assert_called_with("bla/a")


def test_get_secret_no_verify():
    client_obj = get_client(verify=False)

    assert client_obj.session.verify is False


def test_list_secrets(mock_hvac):
    mock_hvac.list.return_value = {"data": {"keys": ["b"]}}

    assert get_client().list_secrets("a") == ["b"]

    mock_hvac.list.assert_called_with("bla/a")


def test_list_secrets_empty(mock_hvac):
    mock_hvac.list.return_value = None

    assert get_client().list_secrets("a") == []

    mock_hvac.list.assert_called_with("bla/a")


def test_delete_secret(mock_hvac):

    get_client().delete_secret("a")

    mock_hvac.delete.assert_called_with("bla/a")


def test_set_secret(mock_hvac):

    get_client()._set_secret("a", "b")

    mock_hvac.write.assert_called_with("bla/a", value="b")


def test_set_context_manager(mocker):
    client_obj = get_client()

    session_exit = mocker.patch.object(client_obj.session, "__exit__")

    assert not session_exit.called

    with client_obj as c:
        assert client_obj is c

    assert session_exit.called


@pytest.mark.parametrize(
    "hvac_exc, vault_cli_exc",
    [
        (hvac.exceptions.Forbidden, exceptions.VaultForbidden),
        (hvac.exceptions.InvalidRequest, exceptions.VaultInvalidRequest),
        (hvac.exceptions.Unauthorized, exceptions.VaultUnauthorized),
        (hvac.exceptions.InternalServerError, exceptions.VaultInternalServerError),
        (hvac.exceptions.VaultDown, exceptions.VaultSealed),
        (hvac.exceptions.UnexpectedError, exceptions.VaultAPIException),
    ],
)
def test_handle_errors(hvac_exc, vault_cli_exc):
    with pytest.raises(vault_cli_exc):
        with client.handle_errors():
            raise hvac_exc


def test_handle_error_json():
    with pytest.raises(exceptions.VaultNonJsonResponse):
        with client.handle_errors():
            json.loads("{")