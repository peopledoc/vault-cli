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

        def _authenticate_certificate(self, *args, **kwargs):
            pass

    TestVaultClient(verify=False, url="yay", login_cert="a", login_cert_key="b").auth()

    assert called_with == {
        "verify": False,
        "url": "yay",
        "login_cert": "a",
        "login_cert_key": "b",
    }


@pytest.mark.parametrize(
    "test_kwargs, expected",
    [
        ({"token": "yay"}, ["token", "yay"]),
        ({"username": "a", "password": "b"}, ["userpass", "a", "b"]),
        ({"login_cert": "a", "login_cert_key": "b"}, ["certificate"]),
    ],
)
def test_vault_client_base_authenticate(test_kwargs, expected):
    auth_params = []

    class TestVaultClient(client.VaultClientBase):
        def _init_client(self, **kwargs):
            pass

        def _authenticate_token(self, token):
            auth_params.extend(["token", token])

        def _authenticate_certificate(self):
            auth_params.extend(["certificate"])

        def _authenticate_userpass(self, username, password):
            auth_params.extend(["userpass", username, password])

    TestVaultClient(**test_kwargs).auth()

    assert auth_params == expected


def test_vault_client_base_username_without_password(vault):

    vault.username = "yay"

    with pytest.raises(exceptions.VaultAuthenticationError):
        vault.auth()


def test_vault_client_base_login_cert_without_key(vault):
    vault.login_cert = "yay"

    with pytest.raises(exceptions.VaultAuthenticationError):
        vault.auth()


def test_vault_client_base_no_auth(vault):

    with pytest.raises(exceptions.VaultAuthenticationError):
        vault.auth()


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
            login_cert=None,
            login_cert_key=None,
        ).auth()

    assert session_kwargs["verify"] == expected


def test_vault_client_base_browse_recursive_secrets(vault):
    vault.db = {"a": "secret-a", "b/c": "secret-bc"}

    result = list(vault._browse_recursive_secrets(""))

    assert result == ["a", "b/c"]


def test_vault_client_base_browse_recursive_secrets_single_secret(vault):

    vault.db = {"a": "secret-a"}

    result = list(vault._browse_recursive_secrets("a"))

    assert result == ["a"]


def test_vault_client_base_get_all_secrets(vault):
    vault.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault.get_all_secrets("a", "")

    assert result == {"a": {"c": "secret-ac"}, "b": "secret-b"}

    result = vault.get_all_secrets("a")

    assert result == {"a": {"c": "secret-ac"}}


@pytest.mark.parametrize(
    "input, expected", [("a", {"a/c": "secret-ac"}), ("b", {"b": "secret-b"})]
)
def test_vault_client_base_get_secrets(vault, input, expected):
    vault.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault.get_secrets(input)

    assert result == expected


def test_vault_client_base_delete_all_secrets_generator(vault):
    vault.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault.delete_all_secrets("a", "b", generator=True)

    assert next(result) == "a/c"

    assert vault.db == {"a/c": "secret-ac", "b": "secret-b"}

    assert next(result) == "b"

    assert vault.db == {"b": "secret-b"}

    with pytest.raises(StopIteration):
        next(result)

    assert vault.db == {}


def test_vault_client_base_delete_all_secrets_no_generator(vault):
    vault.db = {"a/c": "secret-ac", "b": "secret-b"}

    result = vault.delete_all_secrets("a", "b")

    assert result == ["a/c", "b"]

    assert vault.db == {}


def test_vault_client_base_context_manager(vault):

    with vault as c:
        assert c is vault


def test_vault_client_set_secret(vault):

    vault.set_secret("a/b", "c")

    assert vault.db == {"a/b": "c"}


@pytest.mark.parametrize(
    "safe_write, force", [(True, False), (True, None), (False, False)]
)
def test_vault_client_set_secret_overwrite_invalid(vault, safe_write, force):

    vault.db = {"a/b": "d"}
    vault.safe_write = safe_write

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.set_secret("a/b", "c", force=force)

    assert vault.db == {"a/b": "d"}


@pytest.mark.parametrize(
    "safe_write, force, value",
    [(True, True, "c"), (False, None, "c"), (True, None, "d")],
)
def test_vault_client_set_secret_overwrite_valid(vault, safe_write, force, value):

    vault.db = {"a/b": "d"}
    vault.safe_write = safe_write

    vault.set_secret("a/b", value, force=force)

    assert vault.db == {"a/b": value}


def test_vault_client_set_secret_when_there_are_existing_secrets_beneath_path(vault):

    vault.db = {"a/b/c": "d"}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault.set_secret("a/b", "e")

    assert vault.db == {"a/b/c": "d"}


def test_vault_client_set_secret_when_a_parent_is_an_existing_secret(vault):

    vault.db = {"a": "c"}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault.set_secret("a/b", "d")

    assert vault.db == {"a": "c"}


def test_vault_client_set_secret_read_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_get_paths.add("a/b")

    vault.set_secret("a/b", "c")

    assert vault.db == {"a/b": "c"}

    assert len(caplog.records) == 1


def test_vault_client_set_secret_list_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_list_paths.add("a/b")

    vault.set_secret("a/b", "c")

    assert vault.db == {"a/b": "c"}

    assert len(caplog.records) == 1


def test_vault_client_set_secret_read_parent_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_get_paths.add("a")

    vault.set_secret("a/b", "c")

    assert vault.db == {"a/b": "c"}

    assert len(caplog.records) == 1


def test_vault_client_move_secrets(vault):

    vault.db = {"a/b": "c", "a/d": "e"}

    vault.move_secrets("a", "d")

    assert vault.db == {"d/b": "c", "d/d": "e"}


def test_vault_client_move_secrets_generator(vault):

    vault.db = {"a/b": "c", "a/d": "e"}

    result = vault.move_secrets("a", "f", generator=True)

    assert next(result) == ("a/b", "f/b")

    assert vault.db == {"a/b": "c", "a/d": "e"}

    assert next(result) == ("a/d", "f/d")

    assert vault.db == {"f/b": "c", "a/d": "e"}

    with pytest.raises(StopIteration):
        next(result)

    assert vault.db == {"f/b": "c", "f/d": "e"}


def test_vault_client_move_secrets_overwrite(vault):

    vault.db = {"a": "c", "b": "d"}

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.move_secrets("a", "b")

    assert vault.db == {"a": "c", "b": "d"}


def test_vault_client_move_secrets_overwrite_force(vault):

    vault.db = {"a": "c", "b": "d"}

    vault.move_secrets("a", "b", force=True)

    assert vault.db == {"b": "c"}
