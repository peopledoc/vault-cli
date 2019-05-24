import json


class VaultException(Exception):
    pass


class VaultOverwriteSecretError(VaultException):
    def __init__(self, message: str = "", *, path: str):
        self.path = path
        super().__init__(message)

    def __str__(self):
        return f"VaultOverwriteSecretError: Secret at {self.path} already exists"


class VaultMixSecretAndFolder(VaultException):
    pass


class VaultAPIException(VaultException):
    def __init__(self, status_code: int, body: str, *args):
        super(VaultAPIException, self).__init__(*args)
        self.status_code = status_code
        try:
            self.error = "\n".join(json.loads(body)["errors"])
        except Exception:
            self.error = body

    def __str__(self) -> str:
        return 'status={} error="{}"'.format(self.status_code, self.error)


class VaultSecretDoesNotExist(VaultAPIException):
    pass
