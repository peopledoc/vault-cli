import pytest

from vault_cli import client, exceptions


def get_client(backend, **additional_kwargs):
    kwargs = {
        "backend": backend,
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
    return client.get_client_from_kwargs(**kwargs)


@pytest.fixture(params=["requests", "hvac"])
def any_backend(request):
    yield request.param


def test_token(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get(
        "http://vault:8000/v1/bla/a",
        request_headers={"X-Vault-Token": "tok"},
        json={"data": {"value": "b"}},
    )

    client_obj.get_secret("a")

    assert requests_mock.called


def test_userpass(requests_mock, any_backend):
    requests_mock.post(
        "http://vault:8000/v1/auth/userpass/login/myuser",
        json={"auth": {"client_token": "newtok"}},
    )

    # Initialize a client, check that we get a token
    client_obj = get_client(
        backend=any_backend, token=None, username="myuser", password="pass"
    )

    # Check that the token is used
    requests_mock.get(
        "http://vault:8000/v1/bla/a",
        request_headers={"X-Vault-Token": "newtok"},
        json={"data": {"value": "b"}},
    )
    assert client_obj.get_secret("a") == "b"

    # Check that we sent the right pasword
    assert requests_mock.request_history[0].json() == {"password": "pass"}


def test_get_secret(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get("http://vault:8000/v1/bla/a", json={"data": {"value": "b"}})
    assert client_obj.get_secret("a") == "b"


def test_get_secret_not_found(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get(
        "http://vault:8000/v1/bla/a", status_code=404, json={"errors": ["Not found"]}
    )
    with pytest.raises(exceptions.VaultAPIException):
        assert client_obj.get_secret("a")


def test_get_secret_no_verify(requests_mock, any_backend):
    client_obj = get_client(any_backend, verify=False)
    requests_mock.get("http://vault:8000/v1/bla/a", json={"data": {"value": "b"}})
    assert client_obj.get_secret("a") == "b"
    assert requests_mock.last_request.verify is False


def test_list_secrets(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get(
        "http://vault:8000/v1/bla/a?list=True", json={"data": {"keys": ["b"]}}
    )
    assert client_obj.list_secrets("a") == ["b"]


def test_list_secrets_empty(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get(
        "http://vault:8000/v1/bla/a?list=True",
        status_code=404,
        json={"errors": ["not found"]},
    )
    assert client_obj.list_secrets("a") == []


def test_list_secrets_other_error(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.get(
        "http://vault:8000/v1/bla/a?list=True",
        status_code=500,
        json={"errors": ["not found"]},
    )

    with pytest.raises(Exception):
        client_obj.list_secrets("a")


def test_delete_secret(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    requests_mock.delete("http://vault:8000/v1/bla/a", status_code=204)
    client_obj.delete_secret("a")

    assert requests_mock.called


def test_set_secret(requests_mock, any_backend):
    client_obj = get_client(any_backend)
    # Both post and put can be used
    requests_mock.get("http://vault:8000/v1/bla/a", status_code=404)
    requests_mock.get("http://vault:8000/v1/bla/a?list=True", status_code=404)
    requests_mock.put("http://vault:8000/v1/bla/a", status_code=204, json={})
    requests_mock.post("http://vault:8000/v1/bla/a", status_code=204, json={})
    client_obj.set_secret("a", "b")

    assert requests_mock.called
    assert requests_mock.request_history[2].json() == {"value": "b"}


def test_set_context_manager(any_backend):
    client_obj = get_client(any_backend)
    with client_obj as c:
        assert client_obj is c

    # Assert connection is closed ?
    # At least we make sure our context manager doesn't crash.


@pytest.mark.parametrize(
    "status, exception",
    [
        (417, exceptions.VaultAPIException),
        (400, exceptions.VaultInvalidRequest),
        (401, exceptions.VaultUnauthorized),
        (403, exceptions.VaultForbidden),
        (404, exceptions.VaultSecretNotFound),
        (500, exceptions.VaultInternalServerError),
        (503, exceptions.VaultSealed),
    ],
)
def test_exceptions(requests_mock, any_backend, status, exception):
    client_obj = get_client(any_backend)

    requests_mock.get("http://vault:8000/v1/bla/a", status_code=status)

    with pytest.raises(exception):
        client_obj.get_secret("a")


def test_non_json(requests_mock, any_backend):
    client_obj = get_client(any_backend)

    requests_mock.get("http://vault:8000/v1/bla/a", text="{")

    with pytest.raises(exceptions.VaultNonJsonResponse):
        client_obj.get_secret("a")
