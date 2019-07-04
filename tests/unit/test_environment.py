import pytest

from vault_cli import environment


def test_exec_command(mocker):
    execvpe = mocker.patch("os.execvpe")

    environment.exec_command(["a", "b"], {"c": "d"})

    execvpe.assert_called_with("a", ("a", "b"), {"c": "d"})


@pytest.mark.parametrize(
    "path, prefix, key, expected",
    [
        ("", None, "a", "A"),
        ("a", None, "a", "A"),
        ("", None, "a/b", "A_B"),
        ("a", None, "a/b", "A_B"),
        ("a/b", None, "a/b/c", "B_C"),
        ("", "foo", "a", "FOO_A"),
        ("a", "foo", "a", "FOO"),
        ("", "foo", "a/b", "FOO_A_B"),
        ("a", "foo", "a/b", "FOO_B"),
        ("a/b", "foo", "a/b/c", "FOO_C"),
    ],
)
def test_make_env_key(path, prefix, key, expected):
    assert environment.make_env_key(path=path, prefix=prefix, key=key) == expected


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
    assert environment.make_env_value(value=value) == expected
