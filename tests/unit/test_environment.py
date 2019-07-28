import pytest

from vault_cli import environment


def test_exec_command(mocker):
    execvpe = mocker.patch("os.execvpe")

    environment.exec_command(["a", "b"], {"c": "d"})

    execvpe.assert_called_with("a", ("a", "b"), {"c": "d"})


def test_normalize():
    assert environment._normalize("path/to/secret") == "PATH_TO_SECRET"


@pytest.mark.parametrize(
    "base_path, path, prefix, expected",
    [
        ("", "a", None, "A_MYATTR"),
        ("a", "a", None, "A_MYATTR"),
        ("", "a/b", None, "A_B_MYATTR"),
        ("a", "a/b", None, "A_B_MYATTR"),
        ("a/b", "a/b/c", None, "B_C_MYATTR"),
        ("", "a", "foo", "FOO_A_MYATTR"),
        ("a", "a", "foo", "FOO_MYATTR"),
        ("", "a/b", "foo", "FOO_A_B_MYATTR"),
        ("a", "a/b", "foo", "FOO_B_MYATTR"),
        ("a/b", "a/b/c", "foo", "FOO_C_MYATTR"),
    ],
)
def _test_make_env_key(base_path, path, prefix, expected):
    assert (
        environment.make_env_key(
            base_path=base_path, path=path, name="myattr", prefix=prefix
        )
        == expected
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a", "a"),
        (1, "1"),
        (1.2, "1.2"),
        (True, "true"),
        (None, "null"),
        ([1], "[1]"),
        ({"a": ["b"]}, '{"a": ["b"]}'),
    ],
)
def test_make_env_value(value, expected):
    assert environment._make_env_value(value=value) == expected


@pytest.mark.parametrize(
    "key, secret, prefix, expected",
    [
        ("foo", "secret", "", {"FOO": "secret"}),
        ("foo", "secret", "prefix", {"PREFIX": "secret"}),
    ],
)
def test_get_envvars_for_secret(key, secret, prefix, expected):
    assert (
        environment.get_envvars_for_secret(key=key, secret=secret, prefix=prefix)
        == expected
    )


@pytest.mark.parametrize(
    "secrets, path, prefix, expected",
    [
        ({"": {"k1": "v1", "k2": "v2"}}, "a/b", "", {"B_K1": "v1", "B_K2": "v2"}),
        (
            {"": {"k1": "v1", "k2": "v2"}},
            "a/b",
            "YAY",
            {"YAY_K1": "v1", "YAY_K2": "v2"},
        ),
        ({"b": {"k1": "v1", "k2": "v2"}}, "a", "", {"A_B_K1": "v1", "A_B_K2": "v2"}),
        (
            {"b": {"k1": "v1", "k2": "v2"}},
            "a",
            "YAY",
            {"YAY_B_K1": "v1", "YAY_B_K2": "v2"},
        ),
        ({"a/b": {"k1": "v1", "k2": "v2"}}, "", "", {"A_B_K1": "v1", "A_B_K2": "v2"}),
        (
            {"a/b": {"k1": "v1", "k2": "v2"}},
            "",
            "YAY",
            {"YAY_A_B_K1": "v1", "YAY_A_B_K2": "v2"},
        ),
    ],
)
def test_get_envvars_for_secrets(secrets, path, prefix, expected):
    assert (
        environment.get_envvars_for_secrets(secrets=secrets, path=path, prefix=prefix)
        == expected
    )
