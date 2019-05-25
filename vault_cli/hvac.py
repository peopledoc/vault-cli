import contextlib
import json
from typing import Iterable

import hvac

from vault_cli import client, exceptions, sessions, types


class HVACVaultClient(client.VaultClientBase):
    def _init_session(self, url: str, verify: types.VerifyOrCABundle) -> None:
        self.session = sessions.Session()
        with self.handle_errors():
            self.client = hvac.Client(url=url, verify=verify, session=self.session)

    def _authenticate_token(self, token: str) -> None:
        self.client.token = token

    def _authenticate_userpass(self, username: str, password: str) -> None:
        with self.handle_errors():
            self.client.auth_userpass(username, password)

    def list_secrets(self, path: str) -> Iterable[str]:
        with self.handle_errors():
            secrets = self.client.list(self.base_path + path)
        if not secrets:
            return []
        return secrets["data"]["keys"]

    def get_secret(self, path: str) -> types.JSONValue:
        with self.handle_errors():
            secret = self.client.read(self.base_path + path)
        if not secret:
            raise exceptions.VaultSecretNotFound()
        return secret["data"]["value"]

    def delete_secret(self, path: str) -> None:
        with self.handle_errors():
            self.client.delete(self.base_path + path)

    def _set_secret(self, path: str, value: types.JSONValue) -> None:
        with self.handle_errors():
            self.client.write(self.base_path + path, value=value)

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.__exit__(exc_type, exc_value, traceback)

    @contextlib.contextmanager
    def handle_errors(self):
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
