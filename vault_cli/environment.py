import json
import logging
import os
import pathlib
import re
from typing import Dict, Mapping, NoReturn, Optional, Sequence

from vault_cli import client, exceptions

logger = logging.getLogger(__name__)

_replaced_by_underscore = re.compile(r"[/\- ]")
_allowed_named = re.compile(r"[A-Z0-9_]+")


def _normalize(name: str) -> str:
    """
    Change " ", "-" and "/" into "_" in a string
    """
    envvar_name = _replaced_by_underscore.sub("_", name).upper()

    if not _allowed_named.fullmatch(envvar_name):
        raise exceptions.VaultInvalidEnvironmentName(envvar_name)

    return envvar_name


def _make_env_value(value: client.JSONRecursive) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def full_environment(environment: Mapping[str, str]) -> Mapping[str, str]:
    current_env = os.environ.copy()
    current_env.update(environment)
    return current_env


def exec_command(
    command: Sequence[str], environment: Optional[Mapping[str, str]] = None
) -> NoReturn:
    environment = full_environment(environment or {})
    os.execvpe(command[0], tuple(command), environment)


def get_envvars_for_secrets(
    secrets: Dict[str, client.JSONDictRecursive],
    path: str,
    prefix: str,
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
            try:
                env_name = _normalize("_".join(e for e in (prefix, subpath, key) if e))
            except exceptions.VaultInvalidEnvironmentName as exc:
                logger.warning(f"Invalid environment name {exc}, skipping secret value")
                continue
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
