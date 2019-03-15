import pytest

from vault_cli import utils


@pytest.mark.parametrize(
    "dict_obj, expected",
    [
        ({"a": "b", "c": "d"}, {"a": "b", "c": "d"}),
        ({"a/b": "c", "a/d": "e"}, {"a": {"b": "c", "d": "e"}}),
        ({"a/b": "c", "a/d/e": "f"}, {"a": {"b": "c", "d": {"e": "f"}}}),
    ],
)
def test_path_to_nested(dict_obj, expected):
    assert utils.path_to_nested(dict_obj=dict_obj) == expected


def test_path_to_nested_error_last_level():
    # This tests when we're updating and forcing something that was a dict
    # to be another value

    with pytest.raises(ValueError):
        print(utils.path_to_nested(dict_obj={"a/b/c": "d", "a/b": "e"}))


def test_path_to_nested_error_not_last_level():
    # This tests when we're updating and forcing something that was a dict
    # to be a dict

    with pytest.raises(ValueError):
        print(utils.path_to_nested(dict_obj={"a/b": "e", "a/b/c": "d"}))
