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
    def __init__(self, path: str):
        self.path = path
        super().__init__()

    def __str__(self):
        return f"VaultOverwriteSecretError: Secret at {self.path} already exists"


class VaultMixSecretAndFolder(VaultException):
    pass


class VaultRenderTemplateError(VaultException):
    def __str__(self):
        return (
            f"VaultRenderTemplateError: Error while rendering template: {self.args[0]}"
        )


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
    message = "Invalid authentication"


class VaultSecretNotFound(VaultAPIException):
    message = "Secret not found"


class VaultInternalServerError(VaultAPIException):
    message = "Vault server error"


class VaultSealed(VaultAPIException):
    message = "Vault sealed or down"
