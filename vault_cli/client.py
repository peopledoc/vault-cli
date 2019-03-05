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
from typing import Iterable, Optional, Type, Union

from vault_cli import settings, types


def get_client(**kwargs) -> "VaultClientBase":
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


def get_client_from_kwargs(
    backend: Union[str, Type["VaultClientBase"]], **kwargs
) -> "VaultClientBase":
    """
    Initializes a client object from the given final kwargs.
    """
    client_class: Type[VaultClientBase]
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
    def __init__(self, status_code: int, body: str, *args):
        super(VaultAPIException, self).__init__(*args)
        self.status_code = status_code
        try:
            self.error = "\n".join(json.loads(body)["errors"])
        except Exception:
            self.error = body

    def __str__(self) -> str:
        return 'status={} error="{}"'.format(self.status_code, self.error)


class VaultClientBase:

    saved_settings: Optional[types.SettingsDict] = None

    def __init__(
        self,
        url: str,
        verify: bool,
        ca_bundle: str,
        base_path: str,
        certificate: str,
        token: str,
        username: str,
        password: str,
    ):
        """
        All parameters are mandatory but may be None
        """

        verify_ca_bundle: types.VerifyOrCABundle = verify
        if verify and ca_bundle:
            verify_ca_bundle = ca_bundle

        self._init_session(url=url, verify=verify_ca_bundle)

        self.base_path = (base_path or "").rstrip("/") + "/"

        if token:
            self._authenticate_token(token)
        elif certificate:
            self._authenticate_certificate(certificate)
        elif username:
            if not password:
                raise ValueError("Cannot use username without password file")
            self._authenticate_userpass(username=username, password=password)

        else:
            raise ValueError("No authentication method supplied")

    def _get_recursive_secrets(self, path: str) -> types.JSONValue:
        result: types.JSONDict = {}
        path = path.rstrip("/")
        sub_secrets = self.list_secrets(path=path)

        if not sub_secrets:
            return self.get_secret(path=path)

        for key in sub_secrets:
            key_url = "/".join([path, key]) if path else key

            folder = key_url.endswith("/")
            key = key.rstrip("/")
            if folder:
                result[key] = self._get_recursive_secrets(key_url)
                continue

            secret = self.get_secret(path=key_url)
            result[key] = secret

        return result

    def get_all(self, paths: Iterable[str], merged: bool = False) -> types.JSONDict:
        result: types.JSONDict = {}

        for path in paths:
            secrets = self._get_recursive_secrets(path=path)
            result.update(nested_keys(path, secrets))

        if "" in result:
            root_val = result.pop("")
            assert isinstance(root_val, dict)
            result.update(root_val)

        if merged:
            result = self._merge_secrets(result)

        return result

    def _merge_secrets(self, secrets: types.JSONDict) -> types.JSONDict:
        """
        From a dict containing both individual values and folders of
        individual values, create a dict with all the secrets at the same
        level. Mainly meant for when all values are strings or dicts of strings.

        Imagine you've constructed a dict with 3 paths: 2 folders and a secret
        >>> d = {
            "django": {"b": {"m": "n"}, "d": "e"},
            "conf": {"g": "h", "i": "j", "b": {"x": "y"}},
            "some_secret": "l",
        }
        >>> _merge_secrets(d)
        {
            "b": {"x": "y"},
            "d": "e",
            "g": "h",
            "i": "j",
            "some_secret": "l",
        }
        """

        for key, value in list(secrets.items()):
            if isinstance(value, dict):
                secrets.pop(key)
                secrets.update(value)

        return secrets

    def _init_session(self, url: str, verify: types.VerifyOrCABundle) -> None:
        raise NotImplementedError

    def _authenticate_token(self, token: str) -> None:
        raise NotImplementedError

    def _authenticate_certificate(self, certificate: str) -> None:
        raise NotImplementedError

    def _authenticate_userpass(self, username: str, password: str) -> None:
        raise NotImplementedError

    def list_secrets(self, path: str) -> Iterable[str]:
        raise NotImplementedError

    def get_secret(self, path: str) -> types.JSONValue:
        raise NotImplementedError

    def delete_secret(self, path: str) -> None:
        raise NotImplementedError

    def set_secret(self, path: str, value: types.JSONValue) -> None:
        raise NotImplementedError


def nested_keys(path: str, value: types.JSONValue) -> types.JSONDict:
    """
    >>> nested_path('test', 'foo')
    {'test': 'foo'}

    >>> nested_path('test/bla', 'foo')
    {'test': {'bla': 'foo'}}
    """
    try:
        base, subpath = path.strip("/").split("/", 1)
    except ValueError:
        return {path: value}
    return {base: nested_keys(subpath, value)}
