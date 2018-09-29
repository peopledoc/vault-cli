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

from __future__ import absolute_import

import requests
import urllib3

try:
    from urllib.parse import urljoin
except ImportError:
    # Python 2
    from urlparse import urljoin

from vault_cli.client import VaultAPIException
from vault_cli.client import VaultClientBase


class Session(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring
    REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for
    https://github.com/requests/requests/issues/3829
    """
    def merge_environment_settings(self, url, proxies, stream, verify,
                                   *args, **kwargs):
        if self.verify is False:
            verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return super(Session, self).merge_environment_settings(
            url, proxies, stream, verify, *args, **kwargs)


class RequestsVaultClient(VaultClientBase):

    def _init_session(self, url, verify):
        self.session = self.create_session(verify)

        self.url = urljoin(url, "v1/")

    def _full_url(self, path):
        url = urljoin(self.url, self.base_path)
        return urljoin(url, path)

    @staticmethod
    def handle_error(response, expected_code=requests.codes.ok):
        if response.status_code == expected_code:
            return
        raise VaultAPIException(response.status_code, response.text)

    @staticmethod
    def create_session(verify):
        session = Session()
        session.verify = verify
        return session

    def _authenticate_token(self, token):
        self.session.headers.update({'X-Vault-Token': token})

    def _authenticate_userpass(self, username, password):
        data = {"password": password}
        response = self.session.post(self.url + 'auth/userpass/login/' + username,
                                     json=data, headers={})
        self.handle_error(response)

        json_response = response.json()
        self.session.headers.update(
            {'X-Vault-Token': json_response.get('auth').get('client_token')})

    def get_secrets(self, path):
        url = self._full_url(path)
        response = self.session.get(url)
        self.handle_error(response)
        json_response = response.json()
        return json_response['data']

    def get_secret(self, path):
        data = self.get_secrets(path)
        return data['value']

    def list_secrets(self, path):
        url = self._full_url(path).rstrip('/')
        response = self.session.get(url, params={'list': 'true'})
        self.handle_error(response)
        json_response = response.json()
        return json_response['data']['keys']

    def set_secret(self, path, value):
        url = self._full_url(path)
        response = self.session.put(url, json={'value': value})
        self.handle_error(response, requests.codes.no_content)

    def delete_secret(self, path):
        url = self._full_url(path)
        response = self.session.delete(url)
        self.handle_error(response, requests.codes.no_content)
