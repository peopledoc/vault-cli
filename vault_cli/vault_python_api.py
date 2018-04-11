#! /usr/bin/env python

import requests
import json

from urllib.parse import urljoin
from functools import reduce

s = requests.Session()
# s.verify = False

headers = {'X-Vault-Token': ''}
url = 'http://127.0.0.1:8200/v1/'
path = 'secret/'


def userpass_authentication(username, password):
    d = {"password": password}
    r = s.post(url + 'auth/userpass/login/' + username, json=d, headers={})
    json_response = r.json()

    if r.status_code == requests.codes.ok:
        s.headers.update({'X-Vault-Token': json_response.get('auth').get('client_token')})
    else:
        print('Wrong username or password')


# TODO
def certificate_authenticate(cert):
    pass


def get_secret(key):
    r = s.get(reduce(urljoin, (url, path, key)))
    json_response = r.json()

    if r.status_code == requests.codes.ok:
        return json_response.get('data').get('value')


def get_secrets(key):
    r = s.get(reduce(urljoin, (url, path, key)))
    json_response = r.json()

    if r.status_code == requests.codes.ok:
        return json_response.get('data')


def list_secrets():
    r = s.get(reduce(urljoin, (url, path, '?list=true')))
    json_response = r.json()

    if r.status_code == requests.codes.ok:
        return json_response.get('data').get('keys')


def put_secret(key, data):
    headers["Content-Type"] = "application/json"
    r = s.put(reduce(urljoin, (url, path, key)), json=data)

    if r.status_code == 204:
        return 'ok'
    else:
        return ','.join(r.json().get('errors')), r.status_code


def delete_secret(key):
    r = s.delete(reduce(urljoin, (url, path, key)))

    if r.status_code == 204:
        return 'ok'
    else:
        return ','.join(r.json().get('errors')), r.status_code
