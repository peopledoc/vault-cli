import json
import os
import pathlib
from typing import Dict, NoReturn, Optional, Sequence

from vault_cli import types


def _normalize(name: str) -> str:
    return name.upper().replace("/", "_")


def _make_env_value(value: types.JSONValue) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def exec_command(command: Sequence[str], environ: Dict[str, str]) -> NoReturn:
    os.execvpe(command[0], tuple(command), environ)


def get_envvars_for_secret(
    key: str, secret: types.JSONValue, prefix: Optional[str]
) -> Dict[str, str]:
    return {_normalize(prefix or key): _make_env_value(secret)}


def get_envvars_for_secrets(
    secrets: Dict[str, types.JSONDict],
    path: str,
    prefix: Optional[str],
    omit_single_key: bool = False,
) -> Dict[str, str]:
    env_secrets = {}
    if not prefix:
        prefix = pathlib.Path(path).name

    for subpath, values in secrets.items():
        omit = omit_single_key and len(values) == 1
        for key, value in values.items():
            if omit:
                key = ""
            env_name = _normalize("_".join(e for e in (prefix, subpath, key) if e))
            value = _make_env_value(value)
            env_secrets[env_name] = value
    return env_secrets
