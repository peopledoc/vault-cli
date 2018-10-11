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
import json

from vault_cli import settings


def get_client(**kwargs):
    """
    Reads the kwargs and associate them with the
    config files and default values to produce
    a configured client object ready to do calls.

    All parameters are optional.

    Parameters
    ----------

    url : str
        URL of the vault instance (default: https://localhost:8200)
    verify : bool
        Verify HTTPS certificate (default: True)
    certificate : str
        Path to the certificate to connect to vault
    token : str
        Token to connect to Vault
    username : str
        Username used for userpass authentication
    password : str
        Path to the file containing the password for userpass authentication
    base_path : str
        Base path for requests
    backend : str or callable
        Backend or name of the backend to use ('requests', 'hvac')

    Returns
    -------
    An instance of the appropriate subclass of VaultClientBase
    (or whatever was provided as "backend")

    Client instance exposes the following methods:
    - list_secrets(path)
        Returns the name of all elements at the given path.
        Folder names end with "/"
    - get_secret(path)
        Returns the value for the secret at the given path
    - delete_secret(path)
        Deletes the secret at the given path
    - set_secret(path, value)
        Writes the secret at the given path
    - get_all(paths=None)
        Given an iterable of path, recursively returns all
        the secrets
    """
    options = settings.get_vault_options(**kwargs)
    backend = options.pop("backend")
    return get_client_from_kwargs(backend=backend, **options)


def get_client_from_kwargs(backend, **kwargs):
    """
    Initializes a client object from the given final
    kwargs.
    """
    if backend == "requests":
        from vault_cli import requests
        client_class = requests.RequestsVaultClient
    elif backend == "hvac":
        from vault_cli import hvac
        client_class = hvac.HVACVaultClient
    elif callable(backend):
        client_class = backend
    else:
        raise ValueError("Wrong backend value {}".format(backend))

    return client_class(**kwargs)


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


class VaultClientBase():
    def __init__(self, url, verify, base_path,
                 certificate, token, username,
                 password):
        """
        All parameters are mandatory but may be None
        """
        self._init_session(url=url, verify=verify)

        self.base_path = (base_path or "").rstrip("/") + "/"

        if token:
            self._authenticate_token(token)
        elif certificate:
            self._authenticate_certificate(certificate)
        elif username:
            if not password:
                raise ValueError('Cannot use username without password file')
            self._authenticate_userpass(username=username, password=password)

        else:
            raise ValueError("No authentication method supplied")

    def _get_recursive_secrets(self, path):
        result = {}
        path = path.rstrip('/')
        for key in self.list_secrets(path=path):
            key_url = '/'.join([path, key]) if path else key

            folder = key_url.endswith('/')
            key = key.rstrip('/')
            if folder:
                result[key] = self._get_recursive_secrets(key_url)
                continue

            secret = self.get_secret(path=key_url)
            result[key] = secret

        return result

    def get_all(self, paths):
        result = {}

        for path in paths:
            secrets = self._get_recursive_secrets(path=path)
            result.update(nested_keys(path, secrets))

        if "" in result:
            result.update(result.pop(""))

        return result

    def _init_session(self, url, verify):
        raise NotImplementedError

    def _authenticate_token(self, token):
        raise NotImplementedError

    def _authenticate_certificate(self, certificate):
        raise NotImplementedError

    def _authenticate_userpass(self, username, password):
        raise NotImplementedError

    def list_secrets(self, path):
        raise NotImplementedError

    def get_secret(self, path):
        raise NotImplementedError

    def delete_secret(self, path):
        raise NotImplementedError

    def set_secret(self, path, value):
        raise NotImplementedError


def nested_keys(path, value):
    """
    >>> nested_path('test', 'foo')
    {'test': 'foo'}

    >>> nested_path('test/bla', 'foo')
    {'test': {'bla': 'foo'}}
    """
    try:
        base, subpath = path.strip('/').split('/', 1)
    except ValueError:
        return {path: value}
    return {base: nested_keys(subpath, value)}
