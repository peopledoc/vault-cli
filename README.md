# CLI tool for Hashicorp Vault

This tools allows simple interactions with the vault API, allowing
configuration to be done in a separate step using a YAML configuration file.

This is especially interesting if you interact with Hashicorp Vault from
automated deployment tools

## Installation

The tool is packaged but the package is not yet available on pypi.

`pip install vault-cli`

If you wish to use the hvac backend, install with

`pip install vault-cli[hvac]`

## Usage

```console
$ vault --help
Usage: vault [OPTIONS] COMMAND [ARGS]...

  Interact with a Vault. See subcommands for details.

Options:
  -U, --url TEXT               URL of the vault instance
  --verify / --no-verify       Verify HTTPS certificate
  -c, --certificate-file PATH  Certificate to connect to vault. Configuration
                               file can also contain a "certificate" key.
  -T, --token-file PATH        File which contains the token to connect to
                               Vault. Configuration file can also contain a
                               "token" key.
  -u, --username TEXT          Username used for userpass authentication
  -w, --password-file PATH     Can read from stdin if "-" is used as
                               parameter. Configuration file can also contain
                               a "password" key.
  -b, --base-path TEXT         Base path for requests
  --backend TEXT               Name of the backend to use (requests, hvac)
  -h, --help                   Show this message and exit.

Commands:
  delete   Deletes a single secret.
  get      Return a single secret value.
  get-all  Return multiple secrets.
  list     List all the secrets at the given path.
  set      Set a single secret to the given value(s).


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
--- qwerty
...

# Same with only the value of the secret in plain text
$ vault get my_secret --text
qwerty

# Add another secret
$ vault set my_other_secret supersecret
Done

# Add a secret object
$ vault set --yaml blob_secret "{code: supercode}"
Done

# Get all values from the vault in a single command (yaml format)
$ vault get-all
---
my_secret: qwerty
my_other_secret: supersecret
blob_secret:
  code: supercode
test:
  my_folder_secret: sesame

# Get a nested secret based on a path
$ vault get-all test/my_folder_secret
test:
  my_folder_secret: sesame

# Get all values from a folder in a single command (yaml format)
$ vault get-all test my_secret
---
my_secret: qwerty
test:
  my_folder_secret: sesame

# Delete a secret
$ vault delete my_other_secret
Done
```

## Configuration

The first file found in the following location is read, parsed and used:
1. `/etc/vault.yml`
2. `~/.vault.yml`
3. `./.vault.yml`

Any option passed as command line flag will be used over the corresponding
option in the documentation (use either `-` or `_`).

The expected format of the configuration is a mapping, with option names and
their corresponding values:

```yaml
---
username: my_username
password-file: ~/.vault-password
# or
token-file: ~/.vault-token
url: https://vault.mydomain:8200
verify: no
base-path: project/
...
```

Make sure the secret files have their permissions set accordingly.

For simple cases, you can directly define your `token` or `password` in the
file:

```yaml
---
username: my_username
password: secret-password
# or
token: secret-token
url: https://vault.mydomain:8200
verify: no
base-path: project/
...
```

If you do so, make sure the permissions of the configuration file itself are
not too broad

Just note that the `--verify / --no-verify` flag become `verify: yes` or
`verify: no`

## State

The tool is currently in beta mode. It's missing docs, linting, and such.
Be warned.

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
