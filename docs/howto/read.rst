Read secrets from the vault
===========================

Through different commands and options, ``vault-cli`` gives you the primitives to
build powerful scripts to help you integrate the vault to your system.

In the following examples, we'll consider the vault has been set up with the following
secrets:

- at path ``a``, a secret object ``{"b": "c", "d": "e"}``
- at path ``f/g``, a secret object ``{"h": "i"}``

.. note::

    The path you read from depends on your ``base-path``. See :ref:`base-path`.

Browsing the vault
------------------

``vault-cli list`` lets you explore the secrets in a specific path, similar to the
``ls`` command:

.. code:: console

    $ vault-cli list
    a
    f/

    $ vault-cli list f
    g

Reading a secret object or a secret
-----------------------------------

``vault-cli`` uses YAML a lot, for both input and output. Whenever a complex object
is written, e.g. when printing a whole secret object, it is in YAML format.
You can read a whole secret object or a single secret by specifying its key.

.. code:: console

    $ vault-cli get a
    ---
    b: c
    d: e

    $ vault-cli get a b
    c

While most secrets are strings, they can be arbitrary JSON values. By default, strings
will be printed as-is, but complex objects will be printed as YAML. You can force YAML
format whatever the type, by using ``--yaml``:

.. code:: console

    $ vault-cli get --yaml a b
    --- c
    ...


Writing the secret to a file
----------------------------

By default, secret is written to ``stdin``. By specifying a ``--output`` argument, you
can write the secret to a specific file:

.. code:: console

    $ vault-cli get http_certificate current_host --output /etc/ssl/private/http.cert

.. warning::

    Ideally, it's best to avoid writing secrets to the disk (see
    :ref:`writing-to-disk`). This command can still be useful, but consider coupling it
    with ways to write on ephemeral storage, and check your umask__ and the permissions
    of the created file. See :ref:`SystemD` for safe integration strategies.

.. note::

    ``vault-cli env`` also lets you to write secrets to a file just before launching
    an arbitrary command.

.. __: https://en.wikipedia.org/wiki/Umask


Reading multiple secrets at once
--------------------------------

``vault-cli get-all`` lets you recursively read multiple secrets at once. Without
argument (or with ``""``), it will read the whole contents of your ``base-path``. A YAML
object will be printed, where keys are paths, and values are secret objects, having keys
and values themselves:

.. code:: console

    $ vault-cli get-all
    ---
    a:
      b: c
      d: e
    f/g:
      h: i

It's possible to use ``get-all`` on one or more subpaths, or even on single secret
objects:

.. code:: console

    $ vault-cli get-all f
    ---
    f/g:
      h: i

By default, the output is flat: paths are materialized as strings with ``/``. Using
``--no-flat`` gives you a nested version where both paths and keys are represented
as nested objects.

.. code:: console

    $ vault-cli get-all --no-flat f
    ---
    f:
      g:
        h: i

.. warning::

    When using ``--no-flat``, there is no way to know whether the nesting levels are
    actually path parts, secret object keys, or the secrets themselves. The secret
    above could have been created by ``echo '{"g": {"h": "i"}}' | vault-cli set f
    --file=-``.
