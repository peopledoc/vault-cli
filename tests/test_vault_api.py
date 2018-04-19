# -*- coding: utf-8 -*-

# Copyright (C) 2018 PeopleDoc, created by Pierre-Louis Bonicoli

import io
import pytest
from urllib3.response import HTTPResponse

import requests
from vault_cli.vault_python_api import create_session, userpass_authentication


@pytest.fixture
def mock_request(request, mocker):
    response = request.getfuncargvalue('testcase')

    def send(self, request, stream=False, timeout=None, verify=True, cert=None,
             proxies=None):
        data = response['data']
        resp = HTTPResponse(body=io.BytesIO(data), preload_content=False)
        resp.status = response['status']
        resp.reason = response['reason']
        resp.headers = {}
        return self.build_response(request, resp)

    mocker.patch('requests.adapters.HTTPAdapter.send', autospec=True,
                 side_effect=send)


TEST_CASE = [
    {
        'data': b'404 page not found',
        'reason': 'Not Found',
        'status': 404,
    }
]


@pytest.mark.parametrize('testcase', TEST_CASE)
def test_wrong_url(mocker, mock_request, testcase):
    """Check that an exception doesn't occur when URL provided by user is
    wrong"""

    session = create_session(True)
    with pytest.raises(ValueError) as excinfo:
        userpass_authentication(session, 'https://localhost:8200/', 'user', 'pass')
    assert requests.adapters.HTTPAdapter.send.call_count == 1
    assert "Wrong username or password (HTTP code: 404)" == str(excinfo.value)
