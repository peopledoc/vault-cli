import jinja2

from vault_cli.client import VaultClientBase


def render(template: str, client: VaultClientBase) -> str:
    def vault(path):
        return client.get_secret(path)

    return jinja2.Template(template).render(vault=vault)
