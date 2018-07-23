# CLI tool for Hashicorp Vault

This tools allows simple interactions with the vault API, allowing
configuration to be done in a separate step using a YAML configuration file.

This is especially interesting if you interact with Hashicorp Vault from
automated deployment tools

## Installation

The tool is packaged but the package is not yet available on pypi.

`pip install git+https://github.com/peopledoc/vault-cli.git`

## Usage

```console
$ vault --help
Usage: vault [OPTIONS] COMMAND [ARGS]...

Options:
  -U, --url TEXT                URL of the vault instance
  --verify / --no-verify        Verify HTTPS certificate
  -c, --certificate FILENAME    The certificate to connect to vault
  -t, --token TEXT              The token to connect to Vault
  -u, --username TEXT           The username used for userpass authentication
  -w, --password-file FILENAME  Can read from stdin if "-" is used as
                                parameter
  -b, --base-path TEXT          Base path for requests
  -h, --help                    Show this message and exit.

Commands:
  delete
  get
  get-all
  list
  set
```

## Authentication

There are three ways to authenticate against the vault:
- Username and password file: provide a username and a file to read the
  password from. The file may be `-` for stdin.
- Certificate: provide the path to a certificate file. The file may also be
  read from stdin via `-`.
- Token: Bypass authentication step if you already have a valid token.

## Examples
```console
# Connect to https://vault.mydomain:8200/project and list the secrets
$ vault --url=https://vault.mydomain:8200 --certificate=/etc/vault/certificate.key --base-path=project/ list
['mysecret']

# Using the configuration file, get the value for my_secret (yaml format)
$ vault get my_secret
---
my_secret: qwerty

# Set its value to "supersecret"
$ vault set my_other_secret supersecret
ok

# Get all values from the vault in a single command (yaml format)
$ vault get-all
---
my_secret: qwerty
my_other_secret: supersecret

# Delete a secret
$ vault delete my_other_secret
ok
```

## Configuration

All files at the following location are read (in increasing priority order),
parsed, merged and used:
1. `/etc/vault.yml`
2. `~/.vault.yml`
3. `./.vault.yml`

Any option passed as command line flag will be used over the corresponding
option in the documentation.

The expected format of the configuration is a mapping, with option names and
their corresponding values:

```yaml
---
username: my_username
password-file: ~/.vault-password
url: https://vault.mydomain:8200
verify: no
base-path: project/
...
```

Just note that the `--verify / --no-verify` flag become `verify: yes` or
`verify: no`

## State

The tool is currently in beta mode. It's missing docs, tests, CI, pip
packaging, debian packaging, and such. Be warned

## License

Copyright 2018 PeopleDoc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
