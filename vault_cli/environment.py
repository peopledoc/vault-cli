import json
import os
import pathlib
import re
from typing import Dict, NoReturn, Optional, Sequence

from vault_cli import types
_replaced_by_underscore = re.compile(r"[/\- ]")


def _normalize(name: str) -> str:
    """
    Change " ", "-" and "/" into "_" in a string
    """
    return _replaced_by_underscore.sub("_", name).upper()


def _make_env_value(value: types.JSONValue) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def exec_command(command: Sequence[str], environ: Dict[str, str]) -> NoReturn:
    os.execvpe(command[0], tuple(command), environ)


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

def get_envvars(
    vault_client: client.VaultClientBase,
    path: str,
    prefix: str,
    omit_single_key: bool,
    filter_key: str,
) -> Dict[str, str]:
    if filter_key:
        secret = vault_client.get_secret(path=path, key=filter_key)
        return get_envvars_for_secrets(
            path="",
            prefix=prefix,
            secrets={"": {filter_key: secret}},
            omit_single_key=bool(prefix),
        )
    else:
        secrets = vault_client.get_secrets(path=path, relative=True)
        return get_envvars_for_secrets(
            path=path, prefix=prefix, secrets=secrets, omit_single_key=omit_single_key
        )
