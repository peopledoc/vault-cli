import pytest

from vault_cli import settings


@pytest.fixture
def config():
    old = settings.CONFIG
    settings.CONFIG = {}
    yield settings.CONFIG
    settings.CONFIG = old
