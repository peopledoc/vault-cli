.. _library:

Use ``vault_cli`` inside a Python program
=========================================

If you're creating a Python application, you may want to leverage the fact that you
already have a working configuration file on the machine and that vault-cli, as a
Python project, already has all the primitives to access the vault, and you'd be right.

.. note::

    Yes, we are aware of the irony of taking a project that is literally called ``CLI``
    and use it, not as a ``CLI`` but as a library. Maybe we could have picked a better
    name, but that ship has sailed.

Here is a small usage example. Please refer to the :ref:`reference` section for
details::

    >>> import vault_cli

    >>> # Any parameter defined here will have precedence over environment variables
    >>> # and configuration files. Arguments are identical to the flags, with underscores
    >>> # instead of dashes.
    >>> vault = vault_cli.get_client(url="https://vault.mydomain:8200")

    >>> vault.set_secret("some_path", {"key": "mysecret"})

    >>> secret = vault.get_secret("some/path", "key")
    "mysecret"

    >>> vault.list_secrets("")
    ["some/path"]

    >>> vault.get_secrets("")
    {"some/path": {"key": "mysecret}}
