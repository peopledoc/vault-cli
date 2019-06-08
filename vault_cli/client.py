import contextlib
import json
import logging
import pathlib
from typing import Iterable, Optional, Tuple, Type

import hvac
import requests.packages.urllib3

from vault_cli import exceptions, sessions, settings, types, utils

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
    client = get_client_class()(**options)
    client.auth()
    return client


def get_client_class() -> Type["VaultClientBase"]:
    return VaultClient


class VaultClientBase:

    saved_settings: Optional[types.SettingsDict] = None

    def __init__(
        self,
        url: str = settings.DEFAULTS.url,
        verify: bool = settings.DEFAULTS.verify,
        ca_bundle: Optional[str] = settings.DEFAULTS.ca_bundle,
        base_path: Optional[str] = settings.DEFAULTS.base_path,
        login_cert: Optional[str] = settings.DEFAULTS.login_cert,
        login_cert_key: Optional[str] = settings.DEFAULTS.login_cert_key,
        token: Optional[str] = settings.DEFAULTS.token,
        username: Optional[str] = settings.DEFAULTS.username,
        password: Optional[str] = settings.DEFAULTS.password,
        safe_write: bool = settings.DEFAULTS.safe_write,
    ):
        """
        All parameters are mandatory but may be None
        """
        self.url = url
        self.verify: types.VerifyOrCABundle = verify
        self.ca_bundle = ca_bundle
        self.base_path = base_path or ""
        self.login_cert = login_cert
        self.login_cert_key = login_cert_key
        self.token = token
        self.username = username
        self.password = password
        self.safe_write = safe_write

    def auth(self):
        verify_ca_bundle = self.verify
        if self.verify and self.ca_bundle:
            verify_ca_bundle = self.ca_bundle

        # Temporary workaround for https://github.com/urllib3/urllib3/issues/497
        requests.packages.urllib3.disable_warnings()

        self._init_client(
            url=self.url,
            verify=verify_ca_bundle,
            login_cert=self.login_cert,
            login_cert_key=self.login_cert_key,
        )

        self.base_path = (self.base_path or "").rstrip("/") + "/"

        if self.token:
            self._authenticate_token(self.token)
        elif self.login_cert:
            if self.login_cert_key:
                self._authenticate_certificate()
            else:
                raise exceptions.VaultAuthenticationError(
                    "Cannot use certificate file for login without key file"
                )
        elif self.username:
            if not self.password:
                raise exceptions.VaultAuthenticationError(
                    "Cannot use username without password file"
                )
            self._authenticate_userpass(username=self.username, password=self.password)

        else:
            raise exceptions.VaultAuthenticationError(
                "No authentication method supplied"
            )

    def get_force(self, force: Optional[bool]) -> bool:
        return force if force is not None else not self.safe_write

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Implement this with the relevant behaviour in children classes
        for when exiting the client used as context manager.
        """
        pass

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

    def get_all_secrets(self, *paths: str) -> types.JSONDict:
        """
        Takes several paths, return the nested dict of all secrets below
        those paths
        """

        result: types.JSONDict = {}

        for path in paths:
            path_dict = self.get_secrets(path)

            result.update(utils.path_to_nested(path_dict))

        return result

    def get_secrets(self, path: str) -> types.JSONDict:
        """
        Takes a single path an return a path dict with all the secrets
        below this path, recursively
        """
        secrets_paths = self._browse_recursive_secrets(path=path)
        return {subpath: self.get_secret(path=subpath) for subpath in secrets_paths}

    def get_all(self, *args, **kwargs):
        """
        Synonym to get_all_secrets. Can be removed on 0.6.0.
        """
        logger.warning(
            "Using deprecated 'get_all' method. Use 'get_all_secrets' instead."
        )
        return self.get_all_secrets(*args, **kwargs)

    def delete_all_secrets_iter(self, *paths: str) -> Iterable[str]:
        """
        Recursively deletes all the secrets at the given paths.
        """
        for path in paths:
            secrets_paths = self._browse_recursive_secrets(path=path)
            for secret_path in secrets_paths:
                yield secret_path
                self.delete_secret(secret_path)

    def delete_all_secrets(self, *paths: str, generator: bool = False) -> Iterable[str]:
        iterator = self.delete_all_secrets_iter(*paths)
        if generator:
            return iterator
        return list(iterator)

    def move_secrets_iter(
        self, source: str, dest: str, force: Optional[bool] = None
    ) -> Iterable[Tuple[str, str]]:

        source_secrets = self.get_secrets(path=source)

        for old_path, secret in source_secrets.items():
            new_path = dest + old_path[len(source) :]
            secret = source_secrets[old_path]

            yield (old_path, new_path)

            self.set_secret(new_path, secret, force=force)
            self.delete_secret(old_path)

    def move_secrets(
        self, source: str, dest: str, force: bool = False, generator: bool = False
    ) -> Iterable[Tuple[str, str]]:
        iterator = self.move_secrets_iter(source=source, dest=dest, force=force)
        if generator:
            return iterator
        return list(iterator)

    def set_secret(
        self, path: str, value: types.JSONValue, force: Optional[bool] = None
    ) -> None:

        force = self.get_force(force)

        try:
            existing_value = self.get_secret(path=path)
        except exceptions.VaultSecretNotFound:
            pass
        except exceptions.VaultForbidden:
            logger.warning(
                f"Read access '{path}' forbidden: if it exists, secret will be overridden."
            )
        else:
            if not force and existing_value != value:
                raise exceptions.VaultOverwriteSecretError(path=path)

        try:
            problematic_secrets = self.list_secrets(path=path)
            if problematic_secrets:
                secrets = [f"{path}/{secret}" for secret in problematic_secrets]
                raise exceptions.VaultMixSecretAndFolder(
                    f"Cannot create a secret at '{path}' because it is already a "
                    f"folder containing {', '.join(secrets)}"
                )
        except exceptions.VaultForbidden:
            logger.info(
                f"List '{path}' forbidden: if it exists, secret will be overridden."
            )

        path = path.rstrip("/")
        for parent in list(pathlib.PurePath(path).parents)[:-1]:
            try:
                self.get_secret(str(parent))
            except exceptions.VaultSecretNotFound:
                pass
            except exceptions.VaultForbidden:
                logger.info(
                    f"Read access '{parent}' forbidden: cannot check if a secret exists here."
                )
            else:
                raise exceptions.VaultMixSecretAndFolder(
                    f"Cannot create a secret at '{path}' because '{parent}' already exists as a secret"
                )

        self._set_secret(path=path, value=value)

    def _init_client(
        self,
        url: str,
        verify: types.VerifyOrCABundle,
        login_cert: Optional[str],
        login_cert_key: Optional[str],
    ) -> None:
        raise NotImplementedError

    def _authenticate_token(self, token: str) -> None:
        raise NotImplementedError

    def _authenticate_certificate(self) -> None:
        raise NotImplementedError

    def _authenticate_userpass(self, username: str, password: str) -> None:
        raise NotImplementedError

    def list_secrets(self, path: str) -> Iterable[str]:
        raise NotImplementedError

    def get_secret(self, path: str) -> types.JSONValue:
        raise NotImplementedError

    def delete_secret(self, path: str) -> None:
        raise NotImplementedError

    def _set_secret(self, path: str, value: types.JSONValue) -> None:
        raise NotImplementedError


@contextlib.contextmanager
def handle_errors():
    try:
        yield
    except json.decoder.JSONDecodeError as exc:
        raise exceptions.VaultNonJsonResponse(errors=[str(exc)])
    except hvac.exceptions.InvalidRequest as exc:
        raise exceptions.VaultInvalidRequest(errors=exc.errors) from exc
    except hvac.exceptions.Unauthorized as exc:
        raise exceptions.VaultUnauthorized(errors=exc.errors) from exc
    except hvac.exceptions.Forbidden as exc:
        raise exceptions.VaultForbidden(errors=exc.errors) from exc
    except hvac.exceptions.InternalServerError as exc:
        raise exceptions.VaultInternalServerError(errors=exc.errors) from exc
    except hvac.exceptions.VaultDown as exc:
        raise exceptions.VaultSealed(errors=exc.errors) from exc
    except hvac.exceptions.UnexpectedError as exc:
        raise exceptions.VaultAPIException(errors=exc.errors) from exc


class VaultClient(VaultClientBase):
    @handle_errors()
    def _init_client(
        self,
        url: str,
        verify: types.VerifyOrCABundle,
        login_cert: Optional[str],
        login_cert_key: Optional[str],
    ) -> None:
        self.session = sessions.Session()
        self.session.verify = verify

        cert = None
        if login_cert and login_cert_key:
            cert = (login_cert, login_cert_key)

        self.client = hvac.Client(
            url=url, verify=verify, session=self.session, cert=cert
        )

    def _authenticate_token(self, token: str) -> None:
        self.client.token = token

    @handle_errors()
    def _authenticate_userpass(self, username: str, password: str) -> None:
        self.client.auth_userpass(username, password)

    @handle_errors()
    def _authenticate_certificate(self) -> None:
        self.client.auth_tls()

    @handle_errors()
    def list_secrets(self, path: str) -> Iterable[str]:
        secrets = self.client.list(self.base_path + path)
        if not secrets:
            return []
        return secrets["data"]["keys"]

    @handle_errors()
    def get_secret(self, path: str) -> types.JSONValue:
        secret = self.client.read(self.base_path + path)
        if not secret:
            raise exceptions.VaultSecretNotFound()
        return secret["data"]["value"]

    @handle_errors()
    def delete_secret(self, path: str) -> None:
        self.client.delete(self.base_path + path)

    @handle_errors()
    def _set_secret(self, path: str, value: types.JSONValue) -> None:
        self.client.write(self.base_path + path, value=value)

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.__exit__(exc_type, exc_value, traceback)
