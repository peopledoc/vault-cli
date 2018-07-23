#! /usr/bin/env python
"""
Copyright 2018 PeopleDoc
Written by Yann Lachiver
           Joachim Jablon

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import json
import requests
import urllib3

try:
    from urllib.parse import urljoin
except ImportError:
    # Python 2
    from urlparse import urljoin


class Session(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring
    REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for
    https://github.com/requests/requests/issues/3829
    """
    def merge_environment_settings(self, url, proxies, stream, verify,
                                   *args, **kwargs):
        if self.verify is False:
            verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return super(Session, self).merge_environment_settings(
            url, proxies, stream, verify, *args, **kwargs)


class VaultSession(object):
    def __init__(self, url, verify, base_path,
                 certificate=None, token=None, username=None,
                 password_file=None, token_file=None):
        self.session = create_session(verify)

        self.url = urljoin(url, "v1/")
        self.base_path = base_path

        if token_file:
            token = token_file.read().decode("utf-8").strip()

        if token:
            self.session.headers.update({'X-Vault-Token': token})
        elif certificate:
            certificate_authentication(self.session, certificate.read())
        elif username:
            if not password_file:
                raise ValueError('Cannot use username without password file')
            password = password_file.read().decode("utf-8").strip()
            userpass_authentication(self.session, self.url, username, password)
        else:
            raise ValueError("No authentication method supplied")

        if 'X-Vault-Token' not in self.session.headers:
            raise ValueError("Failed authentication")

    def full_url(self, path=None):
        url = urljoin(self.url, self.base_path)
        if path:
            return urljoin(url, path)
        return url


class VaultAPIException(Exception):

    def __init__(self, status_code, body, *args, **kwargs):
        super(VaultAPIException, self).__init__(*args, **kwargs)
        self.status_code = status_code
        try:
            self.error = '\n'.join(json.loads(body)['errors'])
        except Exception:
            self.error = body

    def __str__(self):
        return 'status={} error="{}"'.format(self.status_code, self.error)


def handle_error(response, expected_code=requests.codes.ok):
    if response.status_code == expected_code:
        return
    raise VaultAPIException(response.status_code, response.text)


def create_session(verify):
    session = Session()
    session.verify = verify
    return session


def userpass_authentication(session, url, username, password):
    data = {"password": password}
    response = session.post(url + 'auth/userpass/login/' + username,
                            json=data, headers={})
    handle_error(response)

    if response.status_code == requests.codes.ok:
        json_response = response.json()
        session.headers.update(
            {'X-Vault-Token': json_response.get('auth').get('client_token')})
    else:
        raise ValueError('Wrong username or password (HTTP code: %s)' %
                         response.status_code)


# TODO
def certificate_authentication(session, cert):
    pass


def get_secrets(session, url):
    response = session.get(url)
    handle_error(response)
    json_response = response.json()
    return json_response['data']


def get_secret(session, url):
    data = get_secrets(session, url)
    return data['value']


def get_recursive_secrets(session, url):
    result = {}
    for key in list_secrets(session=session, url=url):
        key_url = '/'.join([url.rstrip('/'), key])

        if key_url.endswith('/'):
            result[key.rstrip('/')] = get_recursive_secrets(session, key_url)
            continue

        secret = get_secret(session=session, url=key_url)
        if secret:
            result[key] = secret
    return result


def list_secrets(session, url):
    response = session.get(url.rstrip('/'), params={'list': 'true'})
    handle_error(response)
    json_response = response.json()
    return json_response['data']['keys']


def put_secret(session, url, data):
    response = session.put(url, json=data)
    handle_error(response, requests.codes.no_content)


def delete_secret(session, url):
    response = session.delete(url)
    handle_error(response, requests.codes.no_content)


def is_dir(session, url, path):
    """
    Returns True if the given path is a dir
    """
    if not path:
        # The top level dir is a dir
        return True

    path = path.strip("/")
    try:
        parent, subpath = path.rsplit("/", 1)
    except ValueError:
        parent, subpath = "", path

    return subpath + "/" in list_secrets(session, urljoin(url, parent))
