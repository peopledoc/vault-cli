import os

import pytest

from vault_cli import settings


@pytest.fixture(autouse=True)
def isolate_tests():

    for key in os.environ:
        if key.startswith(settings.ENV_PREFIX):
            os.environ.pop(key)


@pytest.fixture
def environ(mocker):
    env = {}
    mocker.patch("os.environ", env)
    return env
