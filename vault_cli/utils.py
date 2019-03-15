from vault_cli import types


def path_to_nested(dict_obj: types.JSONDict) -> types.JSONDict:
    """
    Transform a dict with paths as keys into a nested
    dict
    >>> path_to_nested ({"a/b/c": "d", "a/e": "f"})
    {"a": {"b": {"c": "d"}, "e": "f"}}

    If 2 unconsistent values are detected, fails with ValueError:
    >>> path_to_nested ({"a/b/c": "d", "a/b": "e"})
    ValueError()
    """

    for path in list(dict_obj):
        working_dict = dict_obj

        value = dict_obj.pop(path)

        *folders, subpath = path.strip("/").split("/")

        for folder in folders:
            sub_dict = working_dict.setdefault(folder, {})
            if not isinstance(sub_dict, dict):
                raise ValueError("Inconsistent values detected")
            working_dict = sub_dict

        if subpath in working_dict:
            raise ValueError("Inconsistent values detected")
        working_dict[subpath] = value
    return dict_obj
