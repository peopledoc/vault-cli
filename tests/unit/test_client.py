import pytest

from vault_cli import client


@pytest.mark.parametrize("backend, mock", [
    ("requests", "vault_cli.requests.RequestsVaultClient"),
    ("hvac", "vault_cli.hvac.HVACVaultClient"),
])
def test_get_client_from_kwargs(mocker, backend, mock):
    c = mocker.patch(mock)
    client.get_client_from_kwargs(backend, a=1)

    c.assert_called_with(a=1)


def test_get_client_from_kwargs_custom(mocker):
    backend = mocker.MagicMock()
    client.get_client_from_kwargs(backend, a=1)

    backend.assert_called_with(a=1)


def test_get_client_from_kwargs_bad(mocker):
    with pytest.raises(ValueError):
        client.get_client_from_kwargs("nope")


def test_get_client(mocker):
    mocker.patch("vault_cli.settings.build_config_from_files",
                 return_value={"url": "yay"})
    backend = mocker.Mock()

    c = client.get_client(backend=backend, yo=True)

    backend.assert_called_with(yo=True, url="yay")
    assert backend.return_value == c


@pytest.mark.parametrize("error, expected", [
    ("oh no", '''status=404 error="oh no"'''),
    ('''{"errors": ["damn", "gosh"]}''', '''status=404 error="damn\ngosh"'''),
])
def test_vault_api_exception(error, expected):
    exc_str = str(client.VaultAPIException(404, error))

    assert exc_str == expected


@pytest.mark.parametrize("func, args", [
    ("_init_session", "url verify"),
    ("_authenticate_token", "token"),
    ("_authenticate_certificate", "certificate"),
    ("_authenticate_userpass", "username password"),
    ("list_secrets", "path"),
    ("get_secret", "path"),
    ("delete_secret", "path"),
    ("set_secret", "path value"),
])
def test_vault_client_base_not_implemented(func, args):
    class TestVaultClient(client.VaultClientBase):
        def __init__(self):
            pass
    c = TestVaultClient()

    with pytest.raises(NotImplementedError):
        getattr(c, func)(**{name: None for name in args.split()})


@pytest.mark.parametrize("path, value, expected", [
    ('test', 'foo', {'test': 'foo'}),
    ('test/bla', 'foo', {'test': {'bla': 'foo'}}),
])
def test_nested_keys(path, value, expected):
    assert client.nested_keys(path, value) == expected


def test_vault_client_base_call_init_session():
    called_with = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            called_with.update(kwargs)

        def _authenticate_token(self, *args, **kwargs):
            pass

    TestVaultClient(verify=False, url="yay", token="go",
                    base_path=None, certificate=None, username=None,
                    password=None, ca_bundle=None)

    assert called_with == {"verify": False, "url": "yay"}


@pytest.mark.parametrize("test_kwargs, expected", [
    ({"token": "yay"}, ["token", "yay"]),
    (
        {"username": "a", "password": "b"},
        ["userpass", "a", "b"]
    ),
    ({"certificate": "cert"}, ["certificate", "cert"]),
])
def test_vault_client_base_authenticate(test_kwargs, expected):
    auth_params = []

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            pass

        def _authenticate_token(self, token):
            auth_params.extend(["token", token])

        def _authenticate_certificate(self, certificate):
            auth_params.extend(["certificate", certificate])

        def _authenticate_userpass(self, username, password):
            auth_params.extend(["userpass", username, password])

    kwargs = {"token": None,
              "username": None, "password": None,
              "certificate": None}
    kwargs.update(test_kwargs)
    TestVaultClient(verify=False, url=None, base_path=None,
                    ca_bundle=None, **kwargs)

    assert auth_params == expected


def test_vault_client_base_username_without_password():

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            pass

    with pytest.raises(ValueError):
        TestVaultClient(username="yay", password=None,
                        verify=False, url="yay", token=None,
                        base_path=None, certificate=None,
                        ca_bundle=None)


def test_vault_client_base_no_auth():

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            pass

    with pytest.raises(ValueError):
        TestVaultClient(username=None, password=None,
                        verify=False, url="yay", token=None,
                        base_path=None, certificate=None,
                        ca_bundle=None)


def test_vault_client_set_ca_bundle(mocker):

    session_kwargs = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            session_kwargs.update(kwargs)

    with pytest.raises(ValueError):
        TestVaultClient(verify=True, ca_bundle="yay",
                        username=None, password=None, url=None,
                        token=None, base_path=None, certificate=None)

    assert session_kwargs["verify"] == "yay"


def test_vault_client_set_ca_bundle_no_bundle():

    session_kwargs = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            session_kwargs.update(kwargs)

    with pytest.raises(ValueError):
        TestVaultClient(verify=True, ca_bundle=None,
                        username=None, password=None, url=None,
                        token=None, base_path=None, certificate=None)

    assert session_kwargs["verify"] is True


def test_vault_client_set_ca_bundle_no_verify():

    session_kwargs = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_session(self, **kwargs):
            session_kwargs.update(kwargs)

    with pytest.raises(ValueError):
        TestVaultClient(verify=False, ca_bundle="yay",
                        username=None, password=None, url=None,
                        token=None, base_path=None, certificate=None)

    assert session_kwargs["verify"] is False


def test_vault_client_base_get_recursive_secrets():

    class TestVaultClient(client.VaultClientBase):
        def __init__(self):
            pass

        def list_secrets(self, path):
            return {
                "": ["a", "b/"],
                "b": ["c"]
            }[path]

        def get_secret(self, path):
            return {
                "a": "secret-a",
                "b/c": "secret-bc",
            }[path]

    result = TestVaultClient()._get_recursive_secrets("")

    assert result == {'a': 'secret-a', 'b': {'c': 'secret-bc'}}


def test_vault_client_base_get_all():

    class TestVaultClient(client.VaultClientBase):
        def __init__(self):
            pass

        def list_secrets(self, path):
            return {
                "": ["a/", "b"],
                "a": ["c"]
            }[path]

        def get_secret(self, path):
            return {
                "a/c": "secret-ac",
                "b": "secret-b",
            }[path]

    result = TestVaultClient().get_all(["a", ""])

    assert result == {'a': {'c': 'secret-ac'}, 'b': 'secret-b'}

    result = TestVaultClient().get_all(["a"])

    assert result == {'a': {'c': 'secret-ac'}}
