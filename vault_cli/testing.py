import pytest

from vault_cli import client, exceptions


class TestVaultClient(client.VaultClientBase):
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
        self.db = {}
        self.forbidden_list_paths = set()
        self.forbidden_get_paths = set()
        self.freeze_settings = False

        super().__init__(**kwargs)

    def _init_client(self, *args, **kwargs):
        pass

    def _authenticate_token(self, *args, **kwargs):
        pass

    def _authenticate_userpass(self, *args, **kwargs):
        pass

    def _get_secret(self, path):
        path = path.rstrip("/")
        if path in self.forbidden_get_paths:
            raise exceptions.VaultForbidden()
        try:
            return self.db[path]
        except KeyError:
            raise exceptions.VaultSecretNotFound()

    def _list_secrets(self, path):
        path = path.rstrip("/")
        if path in self.forbidden_list_paths:
            raise exceptions.VaultForbidden()
        # Just reproducing in memory the behaviour of the real list_secrets
        # This is complicated enough to have its unit test (in test_testing.py)
        paths = [key for key in self.db if key.startswith(path)]
        result = []
        for element in paths:
            element = element[len(path) + 1 if path else 0 :].split("/", 1)
            if len(element) == 1:
                result.append(element[0])
            else:
                result.append(f"{element[0]}/")

        return sorted(set(result) - {""})

    def _set_secret(self, path, secret):
        self.db[path] = secret

    def _delete_secret(self, path):
        self.db.pop(path, None)

    def _lookup_token(self):
        return {"data": {"expire_time": "2100-01-01T00:00:00"}}


@pytest.fixture
def vault(mocker):
    backend = TestVaultClient()
    mocker.patch("vault_cli.client.get_client_class", return_value=lambda **k: backend)
    yield backend
