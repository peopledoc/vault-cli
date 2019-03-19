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
import logging
from typing import Iterable, Optional, Type, Union

from vault_cli import settings, types

logger = logging.getLogger(__name__)


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
    - get_all_secrets(paths=None)
        Given an iterable of paths, recursively returns all
        the secrets
    - delete_all_secrets(paths=None)
        Given an iterable of paths, recursively yields then deletes
        all the secrets under those paths. Use with extreme caution.
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

    def _browse_recursive_secrets(self, path: str) -> Iterable[str]:
        """
        Given a secret or folder path, return the path of all secrets
        under it (or the path itself)
        """
        # 4 things can happen:
        # - path is "", it's the root (and a folder)
        # - path ends with /, we know it's a folder
        # - path doesn't end with a / and yet it's a folder
        # - path is a secret

        folder = path.endswith("/") or path == ""

        sub_secrets = self.list_secrets(path=path)

        if not folder and not sub_secrets:
            # It's most probably a secret
            yield path

        for key in sub_secrets:
            folder = key.endswith("/")
            key = key.rstrip("/")
            key_url = f"{path}/{key}" if path else key
            if not folder:
                yield key_url
                continue

            for sub_path in self._browse_recursive_secrets(key_url):
                yield sub_path

    def get_all_secrets(self, *paths: str, merged: bool = False) -> types.JSONDict:
        result: types.JSONDict = {}

        for path in paths:
            secrets_paths = self._browse_recursive_secrets(path=path)
            for secret_path in secrets_paths:
                value = self.get_secret(path=secret_path)
                deep_update(dict_obj=result, path=secret_path, value=value)

        if merged:
            result = self._merge_secrets(result)

        return result

    def get_all(self, *args, **kwargs):
        """
        Synonym to get_all_secrets. Can be removed on 0.6.0.
        """
        logger.warning(
            "Using deprecated 'get_all' method. Use 'get_all_secrets' instead."
        )
        return self.get_all_secrets(*args, **kwargs)

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

    def delete_all_secrets(self, *paths: str) -> Iterable[str]:
        """
        Recursively deletes all the secrets at the given paths.
        """
        for path in paths:
            secrets_paths = self._browse_recursive_secrets(path=path)
            for secret_path in secrets_paths:
                yield secret_path
                self.delete_secret(secret_path)

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


def deep_update(
    dict_obj: types.JSONDict, path: str, value: types.JSONValue
) -> types.JSONDict:
    """
    Adds value at the given path, creating necessary levels
    >>> deep_update(dict_obj={"a": "b"}, path="c", "d")
    {"a": "b", "c": "d"}
    >>> deep_update(dict_obj={"a": {"b": "c"}}, path="a/d", "e")
    {"a": {"b": "c", "d": "e"}}
    >>> deep_update(dict_obj={"a": {"b": "c"}}, path="a/d/e", "f")
    {"a": {"b": "c", "d": {"e": "f}}}
    """

    *folders, subpath = path.strip("/").split("/")
    original_dict_obj = dict_obj

    for folder in folders:
        sub_obj = dict_obj.setdefault(folder, {})
        assert isinstance(sub_obj, dict)
        dict_obj = sub_obj

    dict_obj[subpath] = value
    return original_dict_obj
