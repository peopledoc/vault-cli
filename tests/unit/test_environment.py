import pytest

from vault_cli import environment


def test_exec_command(mocker):
    execvpe = mocker.patch("os.execvpe")

    environment.exec_command(["a", "b"], {"c": "d"})

    execvpe.assert_called_with("a", ("a", "b"), {"c": "d"})


@pytest.mark.parametrize(
    "path, key, expected",
    [("", "a", "A"), ("", "a/b", "A_B"), ("a", "a/b", "A_B"), ("a/b", "a/b/c", "B_C")],
)
def test_make_env_key(path, key, expected):
    assert environment.make_env_key(path=path, key=key) == expected


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
