.. _configure:

Configure ``vault-cli``
=======================

There are 3 ways to configure ``vault-cli`` (by decreasing priority):

1. Command-line flags (a.k.a. ``--foo=``)
2. Environment variables (a.k.a ``VAULT_CLI_FOO=``)
3. YAML configuration file (preferred)

The configuration works identically for each way:

+-------------------------+------------------------------+------------------------+
| Configuration file      | Environment variable         | Command-line flag      |
+=========================+==============================+========================+
| ``foo-bar: value``      |                              | ``--foo-bar=value``    |
| ``foo_bar: value``      | ``VAULT_CLI_FOO_BAR=value``  | ``--foo-bar value``    |
+-------------------------+------------------------------+------------------------+
| ``foo-bar: yes``        | ``VAULT_CLI_FOO_BAR=true``   | ``--foo-bar``          |
+-------------------------+------------------------------+------------------------+
| ``foo-bar: no``         | ``VAULT_CLI_FOO_BAR=false``  | ``--no-foo-bar``       |
+-------------------------+------------------------------+------------------------+

For example ``verify: yes`` or ``verify: no`` in the configuration file translates into
``--verify / --no-verify`` as command-line flag or ``VAULT_CLI_VERIFY=true`` as
environment variable.

The environment variable name is always the uppercase underscored name of the equivalent
configuration file option.

For boolean environment variables, when lowercased, the following evaluates to:

- ``True``: ``1``, ``yes``, ``y``, ``t``, ``true``
- ``False``: ``0``, ``no``, ``n``, ``f``, ``false``

The best way to get a up-to-date description of each configuration setting depending
on your version is through:

.. code:: console

   $ vault-cli -h

YAML Configuration files
------------------------

The first file found in the following location is read, parsed and used:

1. ``/etc/vault.yml``
2. ``~/.vault.yml``
3. ``./vault.yml``

The expected format of the configuration is a mapping, with option names
and their corresponding values:

.. code:: yaml

   ---
   username: my_username
   password-file: ~/.vault-password
   # or
   token-file: ~/.vault-token
   url: https://vault.mydomain:8200
   verify: no
   base-path: project/
   ...

Make sure the secret files have their permissions set accordingly.

(Re)create a configuration file based on the current settings
-------------------------------------------------------------

The ``vault-cli dump-config`` will output a YAML file that can be used as a
configuration file, but mind following the caveats:

- Default values will be explicited
- Secrets (token or username) will be included directly, even if they were loaded from
  a dedicated file

.. code:: console

   $ vault-cli --url https://something --token-file /path dump-config > vault.yml
