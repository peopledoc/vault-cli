from vault_cli import metadata
from vault_cli.client import get_client
from vault_cli.exceptions import (
    VaultAPIException,
    VaultException,
    VaultForbidden,
    VaultInternalServerError,
    VaultInvalidRequest,
    VaultMixSecretAndFolder,
    VaultNonJsonResponse,
    VaultOverwriteSecretError,
    VaultSealed,
    VaultSecretNotFound,
    VaultUnauthorized,
)

__all__ = [
    "get_client",
    "VaultException",
    "VaultOverwriteSecretError",
    "VaultMixSecretAndFolder",
    "VaultAPIException",
    "VaultNonJsonResponse",
    "VaultInvalidRequest",
    "VaultUnauthorized",
    "VaultForbidden",
    "VaultSecretNotFound",
    "VaultInternalServerError",
    "VaultSealed",
]

_metadata = metadata.extract_metadata()
__author__ = _metadata["author"]
__author_email__ = _metadata["email"]
__license__ = _metadata["license"]
__url__ = _metadata["url"]
__version__ = _metadata["version"]
