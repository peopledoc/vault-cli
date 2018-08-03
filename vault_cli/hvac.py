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

import hvac

from vault_cli.backend import VaultAPIException
from vault_cli.backend import VaultSessionBase


class VaultSession(VaultSessionBase):

    def init_session(self, url, verify):
        self.client = hvac.Client(url=url, verify=verify)

    def authenticate_token(self, token):
        self.client.token = token

    def authenticate_userpass(self, username, password):
        self.client.auth_userpass(username, password)

    def list_secrets(self, path):
        return self.client.list(self.base_path + path)["data"]["keys"]

    def get_secret(self, path):
        secret = self.client.read(self.base_path + path)
        if not secret:
            raise VaultAPIException(404, "Not found")
        return ["data"]["value"]

    def delete_secret(self, path):
        self.client.delete(self.base_path + path)

    def put_secret(self, path, value):
        self.client.write(self.base_path + path, value=value)
