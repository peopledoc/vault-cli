from vault_cli import exceptions


def test_vault_overwrite_secret_error():
    assert (
        str(exceptions.VaultOverwriteSecretError(path="yay"))
        == "VaultOverwriteSecretError: Secret at yay already exists"
    )
