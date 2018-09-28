"""
Copyright 2018 PeopleDoc
Written by Yann Lachiver
           Joachim Jablon

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

import io
import os
import yaml


# Ordered by increasing priority
CONFIG_FILES = [
    '/etc/vault.yml',
    '~/.vault.yml',
    './.vault.yml',
]

DEFAULTS = {
    'backend': 'requests',
    'base_path': None,
    'certificate': None,
    'password': None,
    'token': None,
    'url': 'https://localhost:8200',
    'username': None,
    'verify': True,
}


def read_config_file(file_path):
    try:
        with open(os.path.expanduser(file_path), "r") as f:
            return yaml.safe_load(f)
    except IOError:
        return {}


def clean_config(config):
    # Because we're modifying the dict during iteration, we need to
    # consolidate the keys into a list
    for key in list(config):
        config[key.replace("-", "_")] = config.pop(key)

    config["certificate"] = read_file(config.get("certificate"))
    config["password"] = read_file(config.get("password"))
    config["token"] = read_file(config.get("token_file"))

    return config


def read_file(path):
    """
    Returns the content of the pointed file
    """
    if path:
        with open(os.path.expanduser(path), 'rb') as file_handler:
            return file_handler.read().decode("utf-8").strip()


def build_config_from_files(config_files):
    config = DEFAULTS.copy()

    for potential_file in config_files:
        partial = clean_config(read_config_file(potential_file))
        config.update(partial)

    return config


# Make sure our config files are not re-read
# everytime we create a backend object
CONFIG = build_config_from_files(CONFIG_FILES)


def get_vault_options(**kwargs):
    values = CONFIG.copy()
    # TODO: Env vars here
    values.update(kwargs)

    return values
