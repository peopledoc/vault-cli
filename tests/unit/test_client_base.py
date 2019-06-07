import pytest

from vault_cli import client, exceptions


def test_get_client(mocker):
    mocker.patch(
        "vault_cli.settings.build_config_from_files", return_value={"url": "yay"}
    )
    vault_client = mocker.patch("vault_cli.client.get_client_class").return_value

    result = client.get_client(yo=True)

    vault_client.assert_called_with(yo=True, url="yay")
    assert vault_client.return_value == result


def test_get_client_class():
    assert client.get_client_class() is client.VaultClient


@pytest.mark.parametrize(
    "errors, expected",
    [
        (None, """Unexpected vault error"""),
        (["damn", "gosh"], """Unexpected vault error\ndamn\ngosh"""),
    ],
)
def test_vault_api_exception(errors, expected):
    exc_str = str(exceptions.VaultAPIException(errors=errors))

    assert exc_str == expected


def test_vault_client_base_call_init_client():
    called_with = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            called_with.update(kwargs)

        def _authenticate_token(self, *args, **kwargs):
            pass

    TestVaultClient(
        verify=False,
        url="yay",
        token="go",
        base_path=None,
        certificate=None,
        username=None,
        password=None,
        ca_bundle=None,
    )

    assert called_with == {"verify": False, "url": "yay"}


@pytest.mark.parametrize(
    "test_kwargs, expected",
    [
        ({"token": "yay"}, ["token", "yay"]),
        ({"username": "a", "password": "b"}, ["userpass", "a", "b"]),
        ({"certificate": "cert"}, ["certificate", "cert"]),
    ],
)
def test_vault_client_base_authenticate(test_kwargs, expected):
    auth_params = []

    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            pass

        def _authenticate_token(self, token):
            auth_params.extend(["token", token])

        def _authenticate_certificate(self, certificate):
            auth_params.extend(["certificate", certificate])

        def _authenticate_userpass(self, username, password):
            auth_params.extend(["userpass", username, password])

    kwargs = {"token": None, "username": None, "password": None, "certificate": None}
    kwargs.update(test_kwargs)
    TestVaultClient(verify=False, url=None, base_path=None, ca_bundle=None, **kwargs)

    assert auth_params == expected


def test_vault_client_base_username_without_password():
    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            pass

    with pytest.raises(exceptions.VaultAuthenticationError):
        TestVaultClient(
            username="yay",
            password=None,
            verify=False,
            url="yay",
            token=None,
            base_path=None,
            certificate=None,
            ca_bundle=None,
        )


def test_vault_client_base_no_auth():
    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            pass

    with pytest.raises(exceptions.VaultAuthenticationError):
        TestVaultClient(
            username=None,
            password=None,
            verify=False,
            url="yay",
            token=None,
            base_path=None,
            certificate=None,
            ca_bundle=None,
        )


@pytest.mark.parametrize(
    "verify, ca_bundle, expected",
    [(True, "yay", "yay"), (True, None, True), (False, "yay", False)],
)
def test_vault_client_ca_bundle_verify(mocker, verify, ca_bundle, expected):

    session_kwargs = {}

    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            session_kwargs.update(kwargs)

    with pytest.raises(exceptions.VaultAuthenticationError):
        TestVaultClient(
            verify=verify,
            ca_bundle=ca_bundle,
            username=None,
            password=None,
            url=None,
            token=None,
            base_path=None,
            certificate=None,
        )

    assert session_kwargs["verify"] == expected


def test_vault_client_base_browse_recursive_secrets(vault_cli):
    vault_cli.db = {"a": "secret-a", "b/c": "secret-bc"}

    result = list(vault_cli._browse_recursive_secrets(""))

    assert result == ["a", "b/c"]


def test_vault_client_base_browse_recursive_secrets_single_secret(vault_cli):

    vault_cli.db = {"a": "secret-a"}

    result = list(vault_cli._browse_recursive_secrets("a"))

    assert result == ["a"]


@pytest.mark.parametrize("method_name", ["get_all", "get_all_secrets"])
def test_vault_client_base_get_all_secrets(method_name, vault_cli):
    vault_cli.db = {"a/c": "secret-ac", "b": "secret-b"}

    get_all_secrets = getattr(vault_cli, method_name)

    result = get_all_secrets("a", "")

    assert result == {"a": {"c": "secret-ac"}, "b": "secret-b"}

    result = get_all_secrets("a")

    assert result == {"a": {"c": "secret-ac"}}


@pytest.mark.parametrize(
    "input, expected", [("a", {"a/c": "secret-ac"}), ("b", {"b": "secret-b"})]
)
def test_vault_client_base_get_secrets(vault_cli, input, expected):
    vault_cli.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault_cli.get_secrets(input)

    assert result == expected


def test_vault_client_base_delete_all_secrets_generator(vault_cli):
    vault_cli.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault_cli.delete_all_secrets("a", "b", generator=True)

    assert next(result) == "a/c"

    assert vault_cli.db == {"a/c": "secret-ac", "b": "secret-b"}

    assert next(result) == "b"

    assert vault_cli.db == {"b": "secret-b"}

    with pytest.raises(StopIteration):
        next(result)

    assert vault_cli.db == {}


def test_vault_client_base_delete_all_secrets_no_generator(vault_cli):
    vault_cli.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault_cli.delete_all_secrets("a", "b")

    assert result == ["a/c", "b"]

    assert vault_cli.db == {}


def test_vault_client_base_context_manager(vault_cli):

    with vault_cli as c:
        assert c is vault_cli


def test_vault_client_set_secret(vault_cli):

    vault_cli.set_secret("a/b", "c")

    assert vault_cli.db == {"a/b": "c"}


def test_vault_client_set_secret_overwrite(vault_cli):

    vault_cli.db = {"a/b": "d"}

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault_cli.set_secret("a/b", "c")

    assert vault_cli.db == {"a/b": "d"}


def test_vault_client_set_secret_overwrite_force(vault_cli):

    vault_cli.db = {"a/b": "d"}

    vault_cli.set_secret("a/b", "c", force=True)

    assert vault_cli.db == {"a/b": "c"}


def test_vault_client_set_secret_when_there_are_existing_secrets_beneath_path(
    vault_cli
):

    vault_cli.db = {"a/b/c": "d"}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault_cli.set_secret("a/b", "e")

    assert vault_cli.db == {"a/b/c": "d"}


def test_vault_client_set_secret_when_a_parent_is_an_existing_secret(vault_cli):

    vault_cli.db = {"a": "c"}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault_cli.set_secret("a/b", "d")

    assert vault_cli.db == {"a": "c"}


def test_vault_client_move_secrets(vault_cli):

    vault_cli.db = {"a/b": "c", "a/d": "e"}

    vault_cli.move_secrets("a", "d")

    assert vault_cli.db == {"d/b": "c", "d/d": "e"}


def test_vault_client_move_secrets_generator(vault_cli):

    vault_cli.db = {"a/b": "c", "a/d": "e"}

    result = vault_cli.move_secrets("a", "f", generator=True)

    assert next(result) == ("a/b", "f/b")

    assert vault_cli.db == {"a/b": "c", "a/d": "e"}

    assert next(result) == ("a/d", "f/d")

    assert vault_cli.db == {"f/b": "c", "a/d": "e"}

    with pytest.raises(StopIteration):
        next(result)

    assert vault_cli.db == {"f/b": "c", "f/d": "e"}


def test_vault_client_move_secrets_overwrite(vault_cli):

    vault_cli.db = {"a": "c", "b": "d"}

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault_cli.move_secrets("a", "b")

    assert vault_cli.db == {"a": "c", "b": "d"}


def test_vault_client_move_secrets_overwrite_force(vault_cli):

    vault_cli.db = {"a": "c", "b": "d"}

    vault_cli.move_secrets("a", "b", force=True)

    assert vault_cli.db == {"b": "c"}
