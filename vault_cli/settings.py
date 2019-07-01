import logging
import os
import sys
from functools import lru_cache
from typing import Dict, Optional, Union

import yaml

from vault_cli import exceptions, types

logger = logging.getLogger(__name__)

ENV_PREFIX = "VAULT_CLI"

# Ordered by increasing priority
CONFIG_FILES = ["./.vault.yml", "~/.vault.yml", "/etc/vault.yml"]


class DEFAULTS:
    base_path = None
    login_cert = None
    login_cert_key = None
    password = None
    token = None
    url = "http://localhost:8200"
    username = None
    verify = True
    ca_bundle = None
    safe_write = False
    render = True

    @staticmethod
    def _as_dict():
        return {k: v for k, v in vars(DEFAULTS).items() if k[0] != "_"}


def read_config_file(file_path: str) -> Optional[types.SettingsDict]:
    try:
        with open(os.path.expanduser(file_path), "r") as f:
            config = yaml.safe_load(f) or {}
            logger.info(
                f"Reading yaml config file at {file_path}, "
                f"contains keys: {', '.join(config)}"
            )
            return config
    except FileNotFoundError:
        logger.debug(f"No config file at {file_path} (skipping)")
    except IOError:
        logger.warning(
            f"Config file exists at {file_path}, but cannot be read. "
            "Have you checked permissions? (skipping)"
        )

    return None


def dash_to_underscores(config: types.SettingsDict) -> types.SettingsDict:
    # Because we're modifying the dict during iteration, we need to
    # consolidate the keys into a list
    return {key.replace("-", "_"): value for key, value in config.items()}


def load_bool(value: str) -> bool:
    lower_value = value.lower()

    if lower_value in ("true", "t", "1", "yes", "y"):
        return True
    elif lower_value in ("false", "f", "0", "no", "n"):
        return False

    raise exceptions.VaultSettingsError("Value {} could not be interpreted as boolean")


def build_config_from_env(environ: Dict[str, str]) -> types.SettingsDict:
    result: types.SettingsDict = {}

    skip_len = len(ENV_PREFIX) + 1

    value: Union[str, bool]

    defaults_dict = DEFAULTS._as_dict()

    for key, str_value in environ.items():

        if not key.startswith(ENV_PREFIX + "_"):
            continue

        key = key[skip_len:].lower()

        if key not in defaults_dict:
            continue

        if isinstance(defaults_dict[key], bool):
            value = load_bool(str_value)
        else:
            value = str_value

        result[key] = value

    return result


def read_all_files(config: types.SettingsDict) -> types.SettingsDict:
    config = config.copy()

    replace_path_with_content(config=config, setting_name="password")
    replace_path_with_content(config=config, setting_name="token")

    return config


def replace_path_with_content(config: types.SettingsDict, setting_name: str) -> None:
    """
    Modifies config dict in place: reads the file at <setting_name>_file
    and put its contents at <setting_name> instead.
    """
    # Files override direct values when both are defined
    filename = config.pop(f"{setting_name}_file", None)
    if filename:
        assert isinstance(filename, str)
        logger.info(f"Reading value of '{setting_name}' from file {filename}")
        config[setting_name] = read_file(filename)


def read_file(path: str) -> Optional[str]:
    """
    Returns the content of the pointed file
    """
    if path == "-":
        return sys.stdin.read().strip()

    with open(os.path.expanduser(path)) as file_handler:

        return file_handler.read().strip()


@lru_cache()
def build_config_from_files(*config_files: str):
    values = DEFAULTS._as_dict()

    for potential_file in config_files:
        file_config = read_config_file(potential_file)
        if file_config is not None:
            file_config = dash_to_underscores(file_config)
            file_config = read_all_files(file_config)
            values.update(file_config)
            break

    return values


def get_vault_options(**kwargs: types.Settings):
    values = build_config_from_files(*CONFIG_FILES).copy()
    values.update(build_config_from_env(os.environ.copy()))
    values.update(kwargs)

    return values


def get_log_level(verbosity: int) -> int:
    """
    Given the number of repetitions of the flag -v,
    returns the desired log level
    """
    return {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(
        min((2, verbosity)), 0
    )
