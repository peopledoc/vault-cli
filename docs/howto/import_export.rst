Move secrets from a Vault cluster to a different Vault cluster
==============================================================

The combination of ``vault-cli get-all`` and ``vault-cli set-all`` gives you a
handy way to move data between two vaults. Let's consider you have prepared
two configuration files ``source.yml`` and ``dest.yml`` containing connection
parameters (see `configure`).

.. code:: console

    $ vault-cli --config-file=source.yml get-all \
        | vault-cli --config-file=dest.yml set-all

That's it.
