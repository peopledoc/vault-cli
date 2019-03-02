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

from typing import Iterable

import hvac
from vault_cli import types
from vault_cli.client import VaultAPIException, VaultClientBase


class HVACVaultClient(VaultClientBase):
    def _init_session(self, url: str, verify: types.VerifyOrCABundle) -> None:
        self.client = hvac.Client(url=url, verify=verify)

    def _authenticate_token(self, token: str) -> None:
        self.client.token = token

    def _authenticate_userpass(self, username: str, password: str) -> None:
        self.client.auth_userpass(username, password)

    def list_secrets(self, path: str) -> Iterable[str]:
        secrets = self.client.list(self.base_path + path)
        if not secrets:
            return []
        return secrets["data"]["keys"]

    def get_secret(self, path: str) -> types.JSONValue:
        secret = self.client.read(self.base_path + path)
        if not secret:
            raise VaultAPIException(404, "Not found")
        return secret["data"]["value"]

    def delete_secret(self, path: str) -> None:
        self.client.delete(self.base_path + path)

    def set_secret(self, path: str, value: types.JSONValue) -> None:
        self.client.write(self.base_path + path, value=value)
