import json

import hvac
import pytest
import requests

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
        "login_cert": None,
        "login_cert_key": None,
        "token": "tok",
        "username": None,
        "password": None,
        "ca_bundle": None,
    }
    kwargs.update(additional_kwargs)
    return client.get_client(**kwargs)


@pytest.fixture
def mock_hvac_v1_class(mocker):
    client = mocker.patch("hvac.Client")
    subclient=client.return_value
    mocker.patch.object(subclient, "read", return_value={"data":{"options": {"version":"1"}}})
    mocker.patch.object(subclient.secrets.kv.v1, "create_or_update_secret", return_value=None)
    mocker.patch.object(subclient.secrets.kv.v1, "read_secret", return_value=None)
    mocker.patch.object(subclient.secrets.kv.v1, "delete_secret", return_value=None)
    mocker.patch.object(subclient.secrets.kv.v1, "list_secrets", return_value=None)
    yield client
    #yield mocker.patch("hvac.Client", lambda *_, **__:client)

@pytest.fixture
def mock_hvac_v1(mock_hvac_v1_class):
    #yield mock_hvac_v1_class
    yield mock_hvac_v1_class.return_value


def test_token(mock_hvac_v1):
    get_client()
    assert mock_hvac_v1.token == "tok"


def test_userpass(mock_hvac_v1):

    get_client(token=None, username="myuser", password="pass")

    mock_hvac_v1.auth_userpass.assert_called_with("myuser", "pass")


def test_certificate(mock_hvac_v1_class, mock_hvac_v1):

    get_client(token=None, login_cert="a", login_cert_key="b")

    assert mock_hvac_v1_class.call_args[1]["cert"] == ("a", "b")
    mock_hvac_v1.auth_tls.assert_called_with()


def test_get_secret(mock_hvac_v1):

    mock_hvac_v1.secrets.kv.v1.read_secret.return_value = {"data": {"value": "b"}}

    assert get_client()._get_secret("bla/a") == {"value": "b"}

    mock_hvac_v1.secrets.kv.v1.read_secret.assert_called_with("bla/a", mount_point="bla")


def test_get_secret_not_found(mock_hvac_v1):

    mock_hvac_v1.secrets.kv.v1.read_secret.return_value = None

    with pytest.raises(exceptions.VaultAPIException):
        assert get_client()._get_secret("bla/a")

    mock_hvac_v1.secrets.kv.v1.read_secret.assert_called_with("bla/a", mount_point="bla")


def test_get_secret_no_verify():
    client_obj = get_client(verify=False)

    assert client_obj.session.verify is False


def test_list_secrets(mock_hvac_v1):
    mock_hvac_v1.secrets.kv.v1.list_secrets.return_value = {"data": {"keys": ["b"]}}

    assert get_client()._list_secrets("bla/a") == ["b"]

    mock_hvac_v1.secrets.kv.v1.list_secrets.assert_called_with("bla/a", mount_point="bla")


def test_list_secrets_sorted(mock_hvac_v1):
    mock_hvac_v1.secrets.kv.v1.list_secrets.return_value = {"data": {"keys": ["b", "A", "c"]}}

    assert get_client()._list_secrets("bla/a") == ["A", "b", "c"]


def test_list_secrets_empty(mock_hvac_v1):
    mock_hvac_v1.secrets.kv.v1.list_secrets.return_value = None

    assert get_client()._list_secrets("bla/a") == []

    mock_hvac_v1.secrets.kv.v1.list_secrets.assert_called_with("bla/a", mount_point="bla")


def test_delete_secret(mock_hvac_v1):

    get_client().delete_secret("a")

    mock_hvac_v1.secrets.kv.v1.delete_secret.assert_called_with("a", mount_point="bla")


def test_delete_secret_one_key(mock_hvac_v1):
    mock_hvac_v1.secrets.kv.v1.read_secret.return_value = {"data": {"value": "b"}}

    get_client().delete_secret("a", "value")

    mock_hvac_v1.secrets.kv.v1.delete_secret.assert_called_with("a",  mount_point="bla")


def test_delete_secret_many_keys(mock_hvac_v1):
    mock_hvac_v1.secrets.kv.v1.read_secret.return_value = {"data": {"a": "A", "b": "B"}}

    get_client().delete_secret("a", "b")

    mock_hvac_v1.secrets.kv.v1.delete_secret.assert_not_called()
    mock_hvac_v1.secrets.kv.v1.create_or_update_secret.assert_called_with("a", secret={"a":"A"}, mount_point="bla")


@pytest.mark.parametrize("existing_mapping", [None, {"data": {"a": "A", "b": "B"}}])
def test_delete_secret_missing_key_or_mapping(mock_hvac_v1, existing_mapping):
    mock_hvac_v1.secrets.kv.v1.read_secret.return_value = existing_mapping

    get_client().delete_secret("a", "c")

    mock_hvac_v1.secrets.kv.v1.delete_secret.assert_not_called()
    mock_hvac_v1.secrets.kv.v1.create_or_update_secret.assert_not_called()


def test_set_secret(mock_hvac_v1):

    get_client()._set_secret("bla/a", {"value": "b"})

    mock_hvac_v1.secrets.kv.v1.create_or_update_secret.assert_called_with("bla/a", secret={"value": "b"}, mount_point="bla")


def test_lookup_token(mock_hvac_v1):

    get_client()._lookup_token()

    mock_hvac_v1.lookup_token.assert_called_with()


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
        (requests.exceptions.ConnectionError, exceptions.VaultConnectionError),
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
