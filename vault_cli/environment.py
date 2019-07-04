import json
import os
import pathlib
from typing import Dict, NoReturn, Optional, Sequence

from vault_cli import types


def make_env_key(path: str, prefix: Optional[str], key: str) -> str:
    if prefix:
        relative = pathlib.Path(prefix) / pathlib.Path(key).relative_to(
            pathlib.Path(path)
        )
    else:
        relative = pathlib.Path(key).relative_to(pathlib.Path(path).parent)
    return str(relative).upper().replace("/", "_")


def make_env_value(value: types.JSONValue) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def exec_command(command: Sequence[str], environ: Dict[str, str]) -> NoReturn:
    os.execvpe(command[0], tuple(command), environ)
