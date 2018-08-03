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
import json


class VaultAPIException(Exception):

    def __init__(self, status_code, body, *args, **kwargs):
        super(VaultAPIException, self).__init__(*args, **kwargs)
        self.status_code = status_code
        try:
            self.error = '\n'.join(json.loads(body)['errors'])
        except Exception:
            self.error = body

    def __str__(self):
        return 'status={} error="{}"'.format(self.status_code, self.error)


class VaultSessionBase():
    def __init__(self, url, verify, base_path,
                 certificate=None, token=None, username=None,
                 password_file=None, token_file=None):
        self.init_session(url=url, verify=verify)

        self.base_path = base_path.rstrip("/") + "/"

        if token_file:
            token = token_file.read().decode("utf-8").strip()

        if token:
            self.authenticate_token(token)
        elif certificate:
            self.authenticate_certificate(
                certificate.read().decode("utf-8").strip())
        elif username:
            if not password_file:
                raise ValueError('Cannot use username without password file')
            password = password_file.read().decode("utf-8").strip()
            self.authenticate_userpass(username=username, password=password)

        else:
            raise ValueError("No authentication method supplied")

    def get_recursive_secrets(self, path):
        result = {}
        for key in self.list_secrets(path=path):
            key_url = '/'.join([path.rstrip('/'), key]) if path else key

            if key_url.endswith('/'):
                result[key.rstrip('/')] = self.get_recursive_secrets(key_url)
                continue

            secret = self.get_secret(path=key_url)
            if secret:
                result[key] = secret
        return result

    def init_session(self, url, verify):
        raise NotImplementedError

    def authenticate_token(self, token):
        raise NotImplementedError

    def authenticate_certificate(certificate):
        raise NotImplementedError

    def authenticate_userpass(self, username, password):
        raise NotImplementedError

    def list_secrets(self, path):
        raise NotImplementedError

    def get_secret(self, path):
        raise NotImplementedError

    def delete_secret(self, path):
        raise NotImplementedError

    def put_secret(self, path, value):
        raise NotImplementedError
