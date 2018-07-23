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

import requests

from urllib.parse import urljoin


class VaultSession(object):
    def __init__(self, url, verify, base_path,
                 certificate=None, token=None, username=None, password_file=None):
        self.session = create_session(verify)

        self.url = urljoin(url, "v1/")
        self.base_path = base_path

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


def create_session(verify):
    session = requests.Session()
    session.verify = verify
    return session


def userpass_authentication(session, url, username, password):
    data = {"password": password}
    response = session.post(url + 'auth/userpass/login/' + username,
                            json=data, headers={})
    json_response = response.json()

    if response.status_code == requests.codes.ok:
        session.headers.update(
            {'X-Vault-Token': json_response.get('auth').get('client_token')})
    else:
        raise ValueError('Wrong username or password')


# TODO
def certificate_authentication(session, cert):
    pass


def get_secret(session, url):
    response = session.get(url)
    json_response = response.json()

    if response.status_code == requests.codes.ok:
        return json_response.get('data').get('value')


def get_secrets(session, url):
    response = session.get(url)
    json_response = response.json()

    if response.status_code == requests.codes.ok:
        return json_response.get('data')


def list_secrets(session, url):
    response = session.get(url.rstrip('/') + '?list=true')
    json_response = response.json()

    if response.status_code == requests.codes.ok:
        return json_response.get('data').get('keys')


def put_secret(session, url, data):
    response = session.put(url, json=data)

    if response.status_code == 204:
        return 'ok'
    else:
        return ','.join(response.json()['errors']), response.status_code


def delete_secret(session, url):
    response = session.delete(url)

    if response.status_code == 204:
        return 'ok'
    else:
        return ','.join(response.json()['errors']), response.status_code
