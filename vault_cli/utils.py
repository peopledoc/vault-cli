from typing import Dict, Iterable


def path_to_nested(dict_obj: Dict) -> Dict:
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


class RecursiveValue:
    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return f'<recursive value "{self.name}">'

    def __getitem__(self, key: str) -> str:
        return str(self)


def extract_error_messages(exc: BaseException) -> Iterable[str]:
    while True:
        exc_str = str(exc).strip()
        yield f"{type(exc).__name__}: {exc_str}"
        opt_exc = exc.__cause__ or exc.__context__
        if not opt_exc:
            break
        exc = opt_exc
