Access a special folder easily
==============================

Among the different possible ways of organizing the vault, it is frequent that
most of your secrets will be stored under one specific path.
``vault-cli`` simplifies your operations by letting you define a ``base-path`` and have
all paths through all commands be relative to that ``base-path``.

Note that starting a path with a ``/`` will let define the full path from the root,
similarily to what you would expect in an UNIX file system.

.. code:: console

    $ export VAULT_CLI_BASE_PATH="/kvv1/myproject"
    $ vault set mysecret key=value

    $ vault get mysecret key
    value

    $ vault get /kvv1/myproject/mysecret key
    value

    $ unset VAULT_CLI_BASE_PATH
    $ vault get mysecret key
    Error: Secret not found
    Secret not found at path '/mysecret'

    $ vault get /kvv1/myproject/mysecret key
    value