import itertools

import pytest

from vault_cli import client, exceptions, testing


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
        TestVaultClient(verify=verify, ca_bundle=ca_bundle).auth()

    assert session_kwargs["verify"] == expected


def test_vault_client_base_browse_recursive_secrets(vault):
    vault.db = {"a": {"value": "secret-a"}, "b/c": {"value": "secret-bc"}}

    result = list(vault._browse_recursive_secrets(""))

    assert result == ["a", "b/c"]


def test_vault_client_base_browse_recursive_secrets_single_secret(vault):

    vault.db = {"a": {"value": "secret-a"}}

    result = list(vault._browse_recursive_secrets("a"))

    assert result == ["a"]


def test_vault_client_base_get_all_secrets(vault):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.get_all_secrets("a", "")

    assert result == {"a": {"c": {"value": "secret-ac"}}, "b": {"value": "secret-b"}}

    result = vault.get_all_secrets("a")

    assert result == {"a": {"c": {"value": "secret-ac"}}}

    result = vault.get_all_secrets("a/")

    assert result == {"a": {"c": {"value": "secret-ac"}}}


def test_vault_client_base_get_all_secrets_flat(vault):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.get_all_secrets("a", "", flat=True)

    assert result == {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.get_all_secrets("a", flat=True)

    assert result == {"a/c": {"value": "secret-ac"}}


@pytest.mark.parametrize(
    "input, expected",
    [
        ("a", {"a/c": {"value": "secret-ac"}}),
        ("b", {"b": {"value": "secret-b"}}),
        ("a/", {"a/c": {"value": "secret-ac"}}),
    ],
)
def test_vault_client_base_get_secrets(vault, input, expected):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.get_secrets(input)
    assert result == expected


@pytest.mark.parametrize(
    "input, expected",
    [("a", {"c": {"value": "secret-ac"}}), ("b", {"": {"value": "secret-b"}})],
)
def test_vault_client_base_get_secrets_relative(vault, input, expected):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.get_secrets(input, relative=True)

    assert result == expected


def test_vault_client_base_delete_all_secrets_generator(vault):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.delete_all_secrets("a", "b", generator=True)

    assert next(result) == "a/c"

    assert vault.db == {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    assert next(result) == "b"

    assert vault.db == {"b": {"value": "secret-b"}}

    with pytest.raises(StopIteration):
        next(result)

    assert vault.db == {}


def test_vault_client_base_delete_all_secrets_no_generator(vault):
    vault.db = {"a/c": {"value": "secret-ac"}, "b": {"value": "secret-b"}}

    result = vault.delete_all_secrets("a", "b")

    assert result == ["a/c", "b"]

    assert vault.db == {}


def test_vault_client_base_delete_all_secrets_trailing_slash(vault):
    vault.db = {"a/c": {"value": "secret-ac"}}

    assert vault.delete_all_secrets("a/") == ["a/c"]

    assert vault.db == {}


def test_vault_client_base_context_manager(vault):

    with vault as c:
        assert c is vault


def test_vault_client_set_secret(vault):

    vault.set_secret("a/b", {"name": "value"})

    assert vault.db == {"a/b": {"name": "value"}}


@pytest.mark.parametrize(
    "safe_write, force", [(True, False), (True, None), (False, False)]
)
def test_vault_client_set_secret_overwrite_invalid(vault, safe_write, force):

    vault.db = {"a/b": {"value": "d"}}
    vault.safe_write = safe_write

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.set_secret("a/b", {"value": "c"}, force=force, update=False)

    assert vault.db == {"a/b": {"value": "d"}}


def test_vault_client_set_secret_with_update(vault):

    vault.db = {"a/b": {"A": "AA"}}
    vault.safe_write = True

    vault.set_secret("a/b", {"B": "BB"}, force=False, update=True)

    assert vault.db == {"a/b": {"A": "AA", "B": "BB"}}


def test_vault_client_set_secret_with_update_overwrite_invalid(vault):

    vault.db = {"a/b": {"A": "AA"}}
    vault.safe_write = True

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.set_secret("a/b", {"A": "BB"}, force=False, update=True)

    assert vault.db == {"a/b": {"A": "AA"}}


@pytest.mark.parametrize(
    "safe_write, force, value",
    [(True, True, "c"), (False, None, "c"), (True, None, "d")],
)
def test_vault_client_set_secret_overwrite_valid(vault, safe_write, force, value):

    vault.db = {"a/b": {"value": "d"}}
    vault.safe_write = safe_write

    vault.set_secret("a/b", {"value": value}, force=force)

    assert vault.db == {"a/b": {"value": value}}


def test_vault_client_set_secret_when_there_are_existing_secrets_beneath_path(vault):

    vault.db = {"a/b/c": {"value": "d"}}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault.set_secret("a/b", {"value": "e"})

    assert vault.db == {"a/b/c": {"value": "d"}}


def test_vault_client_set_secret_when_a_parent_is_an_existing_secret(vault):

    vault.db = {"a": {"value": "c"}}

    with pytest.raises(exceptions.VaultMixSecretAndFolder):
        vault.set_secret("a/b", {"value": "d"})

    assert vault.db == {"a": {"value": "c"}}


def test_vault_client_set_secret_read_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_get_paths.add("a/b")

    vault.set_secret("a/b", {"value": "c"})

    assert vault.db == {"a/b": {"value": "c"}}

    assert len(caplog.records) == 1


def test_vault_client_set_secret_list_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_list_paths.add("a/b")

    vault.set_secret("a/b", {"value": "c"})

    assert vault.db == {"a/b": {"value": "c"}}

    assert len(caplog.records) == 1


def test_vault_client_set_secret_read_parent_not_allowed(vault, caplog):

    caplog.set_level("INFO")

    vault.db = {}
    vault.forbidden_get_paths.add("a")

    vault.set_secret("a/b", {"value": "c"})

    assert vault.db == {"a/b": {"value": "c"}}

    assert len(caplog.records) == 1


def test_vault_client_move_secrets(vault):

    vault.db = {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    vault.move_secrets("a", "d")

    assert vault.db == {"d/b": {"value": "c"}, "d/d": {"value": "e"}}


def test_vault_client_move_secrets_generator(vault):

    vault.db = {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    result = vault.move_secrets("a", "f", generator=True)

    assert next(result) == ("a/b", "f/b")

    assert vault.db == {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    assert next(result) == ("a/d", "f/d")

    assert vault.db == {"f/b": {"value": "c"}, "a/d": {"value": "e"}}

    with pytest.raises(StopIteration):
        next(result)

    assert vault.db == {"f/b": {"value": "c"}, "f/d": {"value": "e"}}


def test_vault_client_move_secrets_overwrite_safe(vault):

    vault.db = {"a": {"value": "c"}, "b": {"value": "d"}}

    vault.safe_write = True

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.move_secrets("a", "b")

    assert vault.db == {"a": {"value": "c"}, "b": {"value": "d"}}


def test_vault_client_move_secrets_overwrite_force(vault):

    vault.db = {"a": {"value": "c"}, "b": {"value": "d"}}

    vault.move_secrets("a", "b", force=True)

    assert vault.db == {"b": {"value": "c"}}


def test_vault_client_copy_secrets(vault):

    vault.db = {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    vault.copy_secrets("a", "d")

    assert vault.db == {
        "a/b": {"value": "c"},
        "a/d": {"value": "e"},
        "d/b": {"value": "c"},
        "d/d": {"value": "e"},
    }


def test_vault_client_copy_secrets_generator(vault):

    vault.db = {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    result = vault.copy_secrets("a", "f", generator=True)

    assert next(result) == ("a/b", "f/b")

    assert vault.db == {"a/b": {"value": "c"}, "a/d": {"value": "e"}}

    assert next(result) == ("a/d", "f/d")

    assert vault.db == {
        "f/b": {"value": "c"},
        "a/b": {"value": "c"},
        "a/d": {"value": "e"},
    }

    with pytest.raises(StopIteration):
        next(result)

    assert vault.db == {
        "a/b": {"value": "c"},
        "a/d": {"value": "e"},
        "f/b": {"value": "c"},
        "f/d": {"value": "e"},
    }


def test_vault_client_copy_secrets_overwrite_safe(vault):

    vault.db = {"a": {"value": "c"}, "b": {"value": "d"}}

    vault.safe_write = True

    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.copy_secrets("a", "b")

    assert vault.db == {"a": {"value": "c"}, "b": {"value": "d"}}


def test_vault_client_copy_secrets_overwrite_force(vault):

    vault.db = {"a": {"value": "c"}, "b": {"value": "d"}}

    vault.copy_secrets("a", "b", force=True)

    assert vault.db == {"a": {"value": "c"}, "b": {"value": "c"}}


def test_vault_client_base_render_template(vault):

    vault.db = {"a/b": {"value": "c"}}

    assert vault.render_template("Hello {{ vault('a/b').value }}") == "Hello c"


@pytest.mark.parametrize("template", ["Hello {{ vault('a/b') }}", "Hello {{"])
def test_vault_client_base_render_template_path_not_found(vault, template):
    with pytest.raises(exceptions.VaultRenderTemplateError):
        vault.render_template(template)


@pytest.mark.parametrize(
    "vault_contents, expected",
    [
        # Secret is not a template
        ({"a": {"value": "b"}}, {"value": "b"}),
        # Secret not a string
        ({"a": {"value": ["yay"]}}, {"value": ["yay"]}),
        # Secret is a template without variable expansion
        ({"a": {"value": "!template!b"}, "b": {"value": "c"}}, {"value": "b"}),
        # Secret is a template
        (
            {"a": {"value": "!template!{{ vault('b').value }}"}, "b": {"value": "c"}},
            {"value": "c"},
        ),
        # Secret is a dict with containing a template
        (
            {
                "a": {"x": "!template!{{ vault('b').value }}", "y": "yay"},
                "b": {"value": "c"},
            },
            {"x": "c", "y": "yay"},
        ),
        # Finite recursion
        (
            {
                "a": {"value": "!template!{{ vault('b').value }}"},
                "b": {"value": "!template!{{ vault('c').value }}"},
                "c": {"value": "d"},
            },
            {"value": "d"},
        ),
        # Infinite Recursion
        (
            {
                "a": {"value": "!template!{{ vault('b').value }}"},
                "b": {"value": "!template!{{ vault('c').value }}"},
                "c": {"value": "!template!{{ vault('a').value }}"},
            },
            {"value": '<recursive value "a">'},
        ),
        # Direct Recursion
        (
            {"a": {"value": "!template!{{ vault('a').value }}"}},
            {"value": '<recursive value "a">'},
        ),
    ],
)
def test_vault_client_base_get_secret(vault, vault_contents, expected):
    vault.db = vault_contents

    assert vault.get_secret("a") == expected


def test_vault_client_base_get_secret_deprecation_warning(vault):
    vault.db = {"a": {"value": "!template!b"}}

    with pytest.warns(DeprecationWarning):
        assert vault.get_secret("a") == {"value": "b"}


def test_vault_client_base_get_secret_template_root(vault):
    vault.base_path = "base"
    vault.db = {"/base/a": {"value": '!template!{{ vault("a").value }} yay'}}

    # In case of erroneous caching, e.g. a different cache entry
    # for /base/a and base/a, we would find '<recursive value "a"> yay yay'
    assert vault.get_secret("/base/a") == {"value": '<recursive value "a"> yay'}


def test_vault_client_base_get_secret_multiple_keys(vault):
    vault.db = {"rabbitmq/creds/role": {"username": "foo", "password": "bar"}}
    assert vault.get_secret("rabbitmq/creds/role") == {
        "username": "foo",
        "password": "bar",
    }


def test_vault_client_base_get_secret_with_dict(vault):
    vault.db = {
        "credentials": {"value": {"username": "foo", "password": "bar"}},
        "dsn": {
            "value": "!template!proto://{{ vault('credentials')['value']['username'] }}:{{ vault('credentials').value.password }}@host"
        },
    }

    assert vault.get_secret("dsn") == {"value": "proto://foo:bar@host"}


def test_vault_client_base_get_secret_not_found(vault):
    vault.db = {}

    with pytest.raises(exceptions.VaultSecretNotFound):
        vault.get_secret("not-exiting")


def test_vault_client_base_get_secret_missing_key(vault):
    vault.db = {"a": {"password": "xxx"}}

    with pytest.raises(exceptions.VaultSecretNotFound):
        vault.get_secret("a", key="username")


def test_vault_client_base_get_secret_template_error(vault, caplog):
    vault.db = {"a": {"key": "!template!{{"}}

    with pytest.raises(exceptions.VaultRenderTemplateError) as exc_info:
        vault.get_secret("a")

    assert str(exc_info.value) == 'Error while rendering secret at path "a"'
    assert (
        str(exc_info.value.__cause__)
        == 'Error while rendering secret value for key "key"'
    )
    assert str(exc_info.value.__cause__.__cause__) == "Jinja2 template syntax error"


def test_vault_client_base_lookup_token(vault):
    assert vault.lookup_token() == {"data": {"expire_time": "2100-01-01T00:00:00"}}


def test_vault_client_base_get_secrets_error(vault, caplog):
    vault.db = {"a": {"value": "b"}, "c": {"value": "d"}}
    vault.forbidden_get_paths = {"c"}

    assert vault.get_secrets("") == {
        "a": {"value": "b"},
        "c": {},
    }
    assert caplog.record_tuples[0] == (
        "vault_cli.client",
        40,
        "VaultForbidden: Insufficient access for interacting with the requested "
        "secret",
    )


def test_vault_client_base_get_secrets_list_forbidden(vault):
    vault.db = {"a": {"value": "b"}, "c": {"value": "d"}}
    vault.forbidden_list_paths = {"c"}

    assert vault.get_secrets("c") == {"c": {"value": "d"}}


@pytest.mark.parametrize(
    "method, params, expected",
    [
        ("get_secret", ["foo"], {"path": "/base/foo"}),
        ("get_secret", ["/foo"], {"path": "/foo"}),
        ("delete_secret", ["foo"], {"path": "/base/foo"}),
        ("delete_secret", ["/foo"], {"path": "/foo"}),
        ("list_secrets", ["foo"], {"path": "/base/foo"}),
        ("list_secrets", ["/foo"], {"path": "/foo"}),
        (
            "set_secret",
            ["foo", {"value": "value"}],
            {"path": "/base/foo", "secret": {"value": "value"}},
        ),
        (
            "set_secret",
            ["/foo", {"value": "value"}],
            {"path": "/foo", "secret": {"value": "value"}},
        ),
    ],
)
def test_vault_client_base_absolute_path(vault, mocker, method, params, expected):
    mocked = mocker.patch(f"vault_cli.testing.TestVaultClient._{method}")
    vault.base_path = "base/"

    getattr(vault, method)(*params)
    mocked.assert_called_with(**expected)


@pytest.mark.parametrize("path, expected", [("foo", "/base/foo"), ("/foo", "/foo")])
def test_vault_client_base_build_full_path(vault, path, expected):
    vault.base_path = "base/"
    assert vault._build_full_path(path) == expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("foo", "/foo/"),
        ("foo/", "/foo/"),
        ("foo//", "/foo/"),
        ("/foo", "/foo/"),
        ("/foo/", "/foo/"),
        ("/foo//", "/foo/"),
    ],
)
def test_vault_client_base_base_path(vault, path, expected):
    vault.base_path = path
    assert vault.base_path == expected


def test_vault_client_base_get_secret_implicit_cache(vault):
    vault.db = {"a": {"value": "b"}}
    assert vault.get_secret("a") == {"value": "b"}
    vault.db = {"a": {"value": "c"}}
    # Value was cached
    assert vault.get_secret("a") == {"value": "b"}


class RaceConditionTestVaultClient(testing.TestVaultClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = itertools.count()

    def _get_secret(self, path):
        if path == "a":
            val = next(self.counter)
            return {"b": f"b{val}", "c": f"c{val}"}
        return super()._get_secret(path)


def test_vault_client_base_get_secret_implicit_cache_no_race_condition():
    # In this test we check that if a value is read several times by
    # a template, implicit caching makes sure we have the same value
    # every time.

    # Values returned by this client keep changing

    vault = RaceConditionTestVaultClient()

    with vault:
        assert vault.get_secret("a") == {"b": "b0", "c": "c0"}
    with vault:
        assert vault.get_secret("a") == {"b": "b1", "c": "c1"}

    vault.db = {"d": {"value": """!template!{{ vault("a").b }}-{{ vault("a").c }}"""}}

    # b2-c3 would be the value if caching didn't work.
    with vault:
        assert vault.get_secret("d") == {"value": "b2-c2"}


def test_vault_client_base_get_secrets_implicit_cache_no_race_condition():
    # In this test, the same value is read twice by get-all and template
    # We check that 2 values are consistent

    vault = RaceConditionTestVaultClient()

    vault.db = {
        "a": {},
        "d": {"value": """!template!{{ vault("a").b }}-{{ vault("a").c }}"""},
    }

    assert vault.get_secrets("") == {
        "a": {"b": "b0", "c": "c0"},
        "d": {"value": "b0-c0"},
    }


def test_vault_client_base_get_secret_explicit_cache(vault):
    vault.db = {"a": {"value": "b"}}
    with vault:
        assert vault.get_secret("a") == {"value": "b"}
        vault.db = {"a": {"value": "c"}}
        # Value not updated
        assert vault.get_secret("a") == {"value": "b"}
    assert vault.get_secret("a") == {"value": "c"}


def test_vault_client_base_set_secrets(vault):
    secrets = {"a": {"b": "c"}, "d/e/f": {"g": "h"}}
    with vault:
        vault.set_secrets(secrets)
    assert vault.db == secrets


def test_vault_client_base_set_secrets_update(vault):
    vault.db = {"a": {"b": "c"}, "d/e/f": {"i": "j"}}
    vault.set_secrets({"d/e/f": {"g": "h"}}, update=True)
    assert vault.db == {"a": {"b": "c"}, "d/e/f": {"g": "h", "i": "j"}}


def test_vault_client_base_set_secrets_force(vault):
    vault.db = {"a": {"b": "c"}, "d/e/f": {"i": "j"}}
    with pytest.raises(exceptions.VaultOverwriteSecretError):
        vault.set_secrets({"d/e/f": {"g": "h"}}, force=False)
