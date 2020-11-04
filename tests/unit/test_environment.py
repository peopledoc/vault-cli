import pytest

from vault_cli import environment, exceptions


def test_exec_command(mocker):
    execvpe = mocker.patch("os.execvpe")

    environment.exec_command(["a", "b"], {"C": "d"})

    execvpe.assert_called_with("a", ("a", "b"), mocker.ANY)
    args, __ = execvpe.call_args
    assert args[2]["C"] == "d"


def test_normalize():
    assert environment._normalize("pa th/to/sec-ret") == "PA_TH_TO_SEC_RET"


def test_normalize_error():
    with pytest.raises(exceptions.VaultInvalidEnvironmentName):
        environment._normalize("a=b")


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
    "secrets, path, prefix, expected",
    [
        ({"": {"k1": "v1"}}, "a/b", "", {"B_K1": "v1"}),
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


def test_get_envvars_for_secrets_invalid(caplog):
    assert (
        environment.get_envvars_for_secrets(
            secrets={"a/b=": {"c": "d"}, "a/e": {"f=": "g"}, "a/h": {"i": "j"}},
            path="",
            prefix="",
        )
        == {"A_H_I": "j"}
    )
    assert caplog.messages == [
        "Invalid environment name A_B=_C, skipping secret value",
        "Invalid environment name A_E_F=, skipping secret value",
    ]


@pytest.mark.parametrize(
    "secrets, path, prefix, expected",
    [
        ({"": {"k1": "v1"}}, "a/b", "", {"B": "v1"}),
        ({"": {"k1": "v1", "k2": "v2"}}, "a/b", "", {"B_K1": "v1", "B_K2": "v2"}),
        ({"": {"k1": "v1"}}, "a/b", "YAY", {"YAY": "v1"}),
        ({"b": {"k1": "v1"}}, "a", "", {"A_B": "v1"}),
        ({"b": {"k1": "v1"}}, "a", "YAY", {"YAY_B": "v1"}),
        ({"a/b": {"k1": "v1"}}, "", "", {"A_B": "v1"}),
        ({"a/b": {"k1": "v1"}}, "", "YAY", {"YAY_A_B": "v1"}),
    ],
)
def test_get_envvars_for_secrets_omit(secrets, path, prefix, expected):
    assert (
        environment.get_envvars_for_secrets(
            secrets=secrets, path=path, prefix=prefix, omit_single_key=True
        )
        == expected
    )


@pytest.mark.parametrize(
    "path, filter_key, prefix, omit_single_key, expected",
    [
        ("a", "", "", True, {"A_B": "d"}),
        ("a", "", "", False, {"A_B_C": "d"}),
        ("a", "", "e", True, {"E_B": "d"}),
        ("a", "", "e", False, {"E_B_C": "d"}),
        ("a/b", "", "", True, {"B": "d"}),
        ("a/b", "", "", False, {"B_C": "d"}),
        ("a/b", "", "e", True, {"E": "d"}),
        ("a/b", "", "e", False, {"E_C": "d"}),
        ("a/b", "c", "", True, {"C": "d"}),
        ("a/b", "c", "", False, {"C": "d"}),
        ("a/b", "c", "e", True, {"E": "d"}),
        ("a/b", "c", "e", False, {"E": "d"}),
    ],
)
def test_get_envvars(vault, path, prefix, omit_single_key, filter_key, expected):
    vault.set_secret("a/b", {"c": "d"})
    assert (
        environment.get_envvars(
            vault_client=vault,
            path=path,
            prefix=prefix,
            omit_single_key=omit_single_key,
            filter_key=filter_key,
        )
        == expected
    )


def test_full_environment(mocker):
    mocker.patch("os.environ", {"A": "B", "C": "D"})
    assert environment.full_environment({"C": "D_", "E": "F"}) == {
        "A": "B",
        "C": "D_",
        "E": "F",
    }
