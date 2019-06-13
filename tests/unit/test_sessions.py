import os

import pytest

from vault_cli import sessions


@pytest.fixture
def reset_requests_ca_bundle():
    requests_ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    yield
    if requests_ca_bundle is not None:
        os.environ["REQUESTS_CA_BUNDLE"] = requests_ca_bundle
    else:
        os.environ.pop("REQUESTS_CA_BUNDLE", None)


@pytest.mark.parametrize(
    "verify, envvar, expected, expected_with_requests",
    [
        (None, None, True, True),
        (True, None, True, True),
        (False, None, False, False),
        ("blu", None, "blu", "blu"),
        (None, "bla", "bla", "bla"),
        (True, "bla", "bla", "bla"),
        (False, "bla", False, "bla"),  # This is the case we're supposedly fixing
        (
            "blu",
            "bla",
            "bla",
            "bla",
        ),  # This might be surprising but it's not important.
    ],
)
def test_session(
    reset_requests_ca_bundle,
    requests_mock,
    verify,
    envvar,
    expected,
    expected_with_requests,
):
    requests_mock.get("https://bla")
    import requests

    vault_cli_session = sessions.Session()
    requests_session = requests.Session()

    if envvar is not None:
        os.environ["REQUESTS_CA_BUNDLE"] = envvar
    if verify is not None:
        vault_cli_session.verify = verify
        requests_session.verify = verify

    vault_cli_session.get("https://bla")

    # If this tests fails here, it means the Session workaround doesn't
    # work anymore
    assert requests_mock.last_request.verify == expected

    requests_session.get("https://bla")

    # If this tests fails here, it means requests have solved the bug
    # and we don't need a workaround anymore
    assert requests_mock.last_request.verify == expected_with_requests
