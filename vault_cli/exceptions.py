from typing import Iterable, Optional


class VaultException(Exception):
    pass


class VaultBackendNotFound(VaultException):
    pass


class VaultAuthenticationError(VaultException):
    pass


class VaultSettingsError(VaultException):
    pass


class VaultOverwriteSecretError(VaultException):
    def __init__(self, path: str, keys: Optional[Iterable[str]] = None):
        self.path = path
        self.keys = keys
        super().__init__()

    def __str__(self):
        s = f"Secret already exists at {self.path}"
        if self.keys:
            s += f" for key{'s' if len(self.keys) > 1 else ''}: {', '.join(self.keys)}"
        return s


class VaultMixSecretAndFolder(VaultException):
    pass


class VaultRenderTemplateError(VaultException):
    pass


class VaultWrongType(VaultException):
    pass


class VaultConnectionError(VaultException):
    message = "Error while connecting to the vault"


class VaultAPIException(VaultException):
    message = "Unexpected vault error"

    def __init__(self, errors: Optional[Iterable[str]] = None):
        self.errors = errors

    def __str__(self) -> str:
        message = self.message
        if self.errors:
            message += "\n" + ("\n".join(self.errors))
        return message


class VaultNonJsonResponse(VaultAPIException):
    message = "Vault answer is not JSON"


class VaultInvalidRequest(VaultAPIException):
    message = "Invalid request"


class VaultUnauthorized(VaultAPIException):
    message = "Missing authentication"


class VaultForbidden(VaultAPIException):
    message = "Insufficient access for interacting with the requested secret"


class VaultSecretNotFound(VaultAPIException):
    message = "Secret not found"


class VaultInternalServerError(VaultAPIException):
    message = "Vault server error"


class VaultSealed(VaultAPIException):
    message = "Vault sealed or down"


class VaultInvalidEnvironmentName(VaultException):
    pass


class VaultSubprocessException(VaultException):
    pass
