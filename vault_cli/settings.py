"""
Copyright 2018 PeopleDoc
Written by Yann Lachiver
           Joachim Jablon
           Jacques Rott

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import sys
from functools import lru_cache

import yaml


ENV_PREFIX = "VAULT_CLI"

# Ordered by increasing priority
CONFIG_FILES = ["./.vault.yml", "~/.vault.yml", "/etc/vault.yml"]

DEFAULTS = {
    "backend": "requests",
    "base_path": None,
    "certificate": None,
    "password": None,
    "token": None,
    "url": "http://localhost:8200",
    "username": None,
    "verify": True,
    "ca_bundle": None,
}


def read_config_file(file_path):
    try:
        with open(os.path.expanduser(file_path), "r") as f:
            return yaml.safe_load(f)
    except IOError:
        return None


def dash_to_underscores(config):
    # Because we're modifying the dict during iteration, we need to
    # consolidate the keys into a list
    return {key.replace("-", "_"): value for key, value in config.items()}


def load_bool(value):
    lower_value = value.lower()

    if lower_value in ("true", "t", "1", "yes", "y"):
        return True
    elif lower_value in ("false", "f", "0", "no", "n"):
        return False

    raise ValueError("Value {} could not be interpreted as boolean")


def build_config_from_env(environ):
    result = {}

    skip_len = len(ENV_PREFIX) + 1

    for key, value in environ.items():

        if not key.startswith(ENV_PREFIX + "_"):
            continue

        key = key[skip_len:].lower()

        if key not in DEFAULTS:
            continue

        if isinstance(DEFAULTS[key], bool):
            value = load_bool(value)

        result[key] = value

    return result


def read_all_files(config):
    config = config.copy()
    # Files override direct values when both are defined
    certificate_file = config.pop("certificate_file", None)
    if certificate_file:
        config["certificate"] = read_file(certificate_file)

    password_file = config.pop("password_file", None)
    if password_file:
        config["password"] = read_file(password_file)

    token_file = config.pop("token_file", None)
    if token_file:
        config["token"] = read_file(token_file)

    return config


def read_file(path):
    """
    Returns the content of the pointed file
    """
    if not path:
        return

    if path == "-":
        return sys.stdin.read().strip()

    with open(os.path.expanduser(path), "rb") as file_handler:
        return file_handler.read().decode("utf-8").strip()


@lru_cache()
def build_config_from_files(*config_files):
    values = DEFAULTS.copy()

    for potential_file in config_files:
        file_config = read_config_file(potential_file)
        if file_config is not None:
            file_config = dash_to_underscores(file_config)
            file_config = read_all_files(file_config)
            values.update(file_config)
            break

    return values


def get_vault_options(**kwargs):
    values = build_config_from_files(*CONFIG_FILES).copy()
    values.update(build_config_from_env(os.environ))
    values.update(kwargs)

    return values
