Authenticate against the vault
==============================

There are three ways to authenticate against the vault:

- Token
- Username and password
- certificate

Token
-----

Either store your token in a dedicated file or store it in the configuration directly:

.. code:: yaml

    ---
    token-file: /path/to/token/file
    # Or
    token: secret-token
    ...

In both cases, make sure the permissions of the file containing the token
are not too broad.

The command-line flag ``--token`` is not available, in order to avoid the token from
being too easily found in the bash history. You can either use the command-line flag
``--token-file=/path/to/token/file`` to read from a file (including ``-`` for ``stdin``)
or the ``VAULT_CLI_TOKEN=secret-token`` environment variable.

Username and password
---------------------

A username and password pair can be used to generate a token:

.. code:: yaml

    ---
    username: foo

    password: secret-password
    # Or
    password-file: /path/to/token/file
    ...

The restrictions on the token apply identically on the password.

Certificate
-----------

.. code:: yaml

    ---
    username: foo

    login-cert: /path/to/public/certificate
    login-cert-key: /path/to/private/key
    ...
