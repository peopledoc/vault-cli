from typing import Iterable

import hvac

from vault_cli import client, exceptions, sessions, types


class HVACVaultClient(client.VaultClientBase):
    def _init_session(self, url: str, verify: types.VerifyOrCABundle) -> None:
        self.session = sessions.Session()
        self.client = hvac.Client(url=url, verify=verify, session=self.session)

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
            raise exceptions.VaultSecretDoesNotExist(404, "Not found")
        return secret["data"]["value"]

    def delete_secret(self, path: str) -> None:
        self.client.delete(self.base_path + path)

    def _set_secret(self, path: str, value: types.JSONValue) -> None:
        self.client.write(self.base_path + path, value=value)

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.__exit__(exc_type, exc_value, traceback)
