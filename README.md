# CLI tool for Hashicorp Vault

This tools allows simple interactions with the vault API, allowing
configuration to be done in a separate step using a YAML configuration file.

This is especially interesting if you interact with Hashicorp Vault from
automated deployment tools.

## Installation

`pip install vault-cli`

Vault-cli only works with python 3.6 and over.

## Usage

```
Usage: vault [OPTIONS] COMMAND [ARGS]...

  Interact with a Vault. See subcommands for details.

  All arguments can be passed by environment variables:
  VAULT_CLI_UPPERCASE_NAME (including VAULT_CLI_PASSWORD and
  VAULT_CLI_TOKEN).

Options:
  -U, --url TEXT                  URL of the vault instance
  --verify / --no-verify          Verify HTTPS certificate
  --ca-bundle PATH                Location of the bundle containing the server
                                  certificate to check against.
  --login-cert PATH               Path to a public client certificate to use
                                  for connecting to vault.
  --login-cert-key PATH           Path to a private client certificate to use
                                  for connecting to vault.
  -T, --token-file PATH           File which contains the token to connect to
                                  Vault. Configuration file can also contain a
                                  "token" key.
  -u, --username TEXT             Username used for userpass authentication
  -w, --password-file PATH        Can read from stdin if "-" is used as
                                  parameter. Configuration file can also
                                  contain a "password" key.
  -b, --base-path TEXT            Base path for requests
  -s, --safe-write / --unsafe-write
                                  When activated, you can't overwrite a secret
                                  without passing "--force" (in commands
                                  "set", "mv", etc)
  --render / --no-render          Render templated values
  -v, --verbose                   Use multiple times to increase verbosity
  --config-file PATH              Config file to use. Use 'no' to disable
                                  config file. Default value: first of
                                  ./vault.yml, ~/.vault.yml, /etc/vault.yml
  -V, --version
  -h, --help                      Show this message and exit.

Commands:
  delete        Delete a single secret.
  delete-all    Delete multiple secrets.
  dump-config   Display settings in the format of a config file.
  env           Launch a command, loading secrets in environment.
  get           Return a single secret value.
  get-all       Return multiple secrets.
  list          List all the secrets at the given path.
  lookup-token  Return information regarding the current token
  mv            Recursively move secrets from source to destination path.
  set           Set a secret.
  template      Render the given template and insert secrets in it.
```

## Authentication

There are three ways to authenticate against the vault:
- Username and password file: provide a username and a file to read the
  password from. The file may be `-` for stdin.
- Client certificate: provide the path to a certificate file.
- Token: Bypass authentication step if you already have a valid token.

## Showcase

### Connect to https://vault.mydomain:8200/project and list the secrets
```console
$ vault --url=https://vault.mydomain:8200 --certificate=/etc/vault/certificate.key --base-path=project/ list
['my_secret']
```

On the following examples, we'll be considering that we have a complete configuration file.

### Read a secret in plain text (default)
```console
$ vault get my_secret value
qwerty
```

### Read a secret in yaml format
```console
$ vault get --yaml my_secret value
--- qwerty
...
```

### Write a secret
```console
$ vault set my_other_secret value=supersecret
Done
```

### Read/write a secret outside the base path
If a base path is defined it will be prepended to all the paths used by vault-cli
except when the paths start by a slash (`/`), those are absolute paths.

```console
$ export VAULT_CLI_BASE_PATH=secretkvv1/myapp/
$ vault set mysecret value=sharedsecret
Done
$ vault get mysecret value
sharedsecret
$ vault get /secretkvv1/myapp/mysecret value
sharedsecret
$ unset VAULT_CLI_BASE_PATH
```


### Write a secret via stdin.
You can use this when the secret has multiple lines or starts with a "-"

```console
$ vault set third_secret certificate=-
----BEGIN SECRET KEY----
...
<hit ctrl+d to end stdin>
Done

vault get third_secret
----BEGIN SECRET KEY----
...
```

Identically, piping allows you to write the content of a file into the vault:

```console
$ cat my_certificate.key | vault set third_secret certificate=-
Done
```

You can also load a key/value mapping in yaml or JSON format from a file:
```console
$ vault set third_secret --file=secret.yaml
Done
```

A special value of "-" for `--file` means that the file is read from stdin.

### Write a secret using an invisible input prompt

This will avoid your secrets to be displayed in plain text in your shell history.

 ```console
 $ vault set mypath --prompt mykey
 Please enter a value for key `mykey` of `mypath`:
 Done
 ```

### Anything following "--" will not be seen as a flag even if it starts with a "-"
```console
$ vault set -- -secret-name -oh-so-secret=xxx
Done

$ vault get -- -secret-name
---
-oh-so-secret: xxx
```

### Protect yourself from overwriting a secret by mistake

```console
vault set a value=b
Done
$ vault --safe-write set a value=c
Error: Secret already exists at a. Use -f to force overwriting.
$ vault --safe-write set -f a value=c
Done
```
(`safe-write` can be set in your configuration file, see details below)

### Get all values from the vault in a single command (yaml format)
```console
$ vault get-all
---
-secret-name:
  -oh-so-secret: xxx
a:
  value: c
my_other_secret:
  value: supersecret
third_secret:
  certificate: '----BEGIN SECRET KEY----

    ...

    '
```

### Get a nested secret based on a path
```console
$ vault set test/my_folder_secret secret=yay
Done

$ vault get-all test/my_folder_secret
---
test:
  my_folder_secret:
    secret: yay

$ vault get-all --flat test/my_folder_secret
---
test/my_folder_secret:
  secret: yay
```

### Get all values recursively from several folders in a single command (yaml format)
```console
$ vault get-all test my_secret
---
my_secret:
  value: qwerty
test:
  my_folder_secret:
    secret: yay

$ vault get-all --flat test my_secret
---
my_secret:
  value: qwerty
test/my_folder_secret:
  secret: yay

```

### Delete a secret
```console
$ vault delete my_other_secret
Done
```

### Move secrets and folders
```console
$ vault mv my_secret test/my_secret
Move 'my_secret' to 'test/my_secret'

$ vault get-all --flat
-secret-name:
  -oh-so-secret: xxx
a:
  value: c
test/my_folder_secret:
  secret: yay
test/my_secret:
  value: qwerty
third_secret:
  certificate: '----BEGIN SECRET KEY----

    ...

    '
```

### Launch a process loading secrets through environment variables
```console
$ vault env --path test/my_secret -- env
...
MY_SECRET_VALUE=qwerty
...
$ vault set foo/bar/service/instance/main dsn=proto://xxx
$ vault env --path test/my_secret:value=MYVAL --path foo/bar/service/instance/main=my -- env
...
MYVAL=qwerty
MY_DSN=proto://xxx
...
```


### Render a template file with values from the vault
```console
$ vault set my_secret username=John password=qwerty
Done

$ vault template mytemplate.j2 > /etc/conf

# mytemplate.j2:
User={{ vault("my_secret").username }}
Password={{ vault("my_secret").password }}

# /etc/conf:
User=John
Password=qwerty
```
(Use `-` for stdin and `-o <file or ->` to specify the file to write to, or stdout).

### (Re)create a configuration file based on the current settings
```console
$ vault --url https://something --token mytoken dump-config > vault.yaml
```

### Delete everything under blob-secret
```console
$ vault delete-all blob-secret
```

### Delete everything, no confirmation
```console
$ vault delete-all --force
```

### Create a templated value
```console
$ vault set path/to/my/service password=foo
$ vault set shortcut dsn='!template!proto://username:{{ vault("path/to/my/service").password }}@host/'
$ vault get shortcut dsn
proto://username:foo@host/
$ vault --no-render get shortcut dsn
!template!proto://username:{{ vault("path/to/my/service").password }}@host/
```
The `vault` function does not render variables recursively.

### Get information on your current token
```
$ vault lookup-token
```

### Use the testing client in your tests

```console
$ pip install vault-cli[testing]
```

```python
# conftest.py (for pytest)
from vault_cli.testing import vault

__all__ = ["vault"]
```
```python
# test_something.py

def test_bla(vault):
    vault.db = {"a/b": "c"}

    assert vault.get_secret("a/b") == "c"

```

## Configuration

The first file found in the following location is read, parsed and used:
1. `/etc/vault.yml`
2. `~/.vault.yml`
3. `./vault.yml`

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
not too broad.

Just note that the `--verify / --no-verify` flag become `verify: yes` or
`verify: no`

All parameters can be defined from environment variables:

```console
$ VAULT_CLI_URL=https://myvault.com vault list
```
The name is always the uppercase underscored name of the equivalent command
line option. Token and password can also be passed as environment variables as
VAULT_CLI_TOKEN and VAULT_CLI_PASSWORD.

## Upgrading

### 1.0

This version includes some breaking changes about key-value mappings management.
In the previous versions of vault-cli, there was an implicit key `value` that
was used everywhere. The goal was to provide a path <-> value abstraction.
But it was hiding the path <-> key/value mapping reality of vault's kv engine.

In this release we removed the implicit ̀`value` key in order to expose a
key/value mapping instead of a single value. Most of the commands have been
updated in order to add the key parameter.

A new option `--omit-single-key` was added to `vault env` in order to ignore
the key when the variable names are built and there is only one key in the
mapping. This option case simplify your migration as there won't be an
additional `_VALUE` suffix added to your environment variables names.

The following list shows how to update your commands:

```sh
(old) vault set path/to/creds xxx
(new) vault set path/to/creds value=xxx

(old) vault get path/to/creds
(new) vault get path/to/creds value

(old) vault env --path path/to/creds=FOO -- env  # FOO=xxx
(new) vault env --path path/to/creds=FOO -- env  # FOO_VALUE=xxx
(new) vault env --path path/to/creds:value=FOO -- env  # FOO=xxx
```

The default output of `vault get-all` has also changed and is now flat by default (this
behavior is controlled with the `--flat/--no-flat` flags).

```sh
$ vault set a/b secret=xxx
$ vault set a/c secret=xxx
$ vault get-all a
---
a/b:
  secret: xxx
a/c:
  secret: xxx
$ vault get-all --no-flat a
---
a:
  b:
    secret: xxx
  c:
    secret: xxx
```

## Integrate with SystemD

See [dedicated document](README-systemd.md).

## Troubleshooting

### `SyntaxError: invalid syntax`

You're most probably using Python 3.5 or below (including Python 2)

## State

The tool is currently in beta mode. It's missing docs and other things.
Be warned.

## Contributing

We welcome any help :) See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright 2018-2019 PeopleDoc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
