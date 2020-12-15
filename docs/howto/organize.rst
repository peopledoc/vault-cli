Reorganize the content of the vault
===================================

``vault-cli`` has a few commands to help you move secrets around and reorganize the
content of the vault.

Copy secrets and folders
------------------------

.. code:: console

    $ vault-cli set a b=c

    $ vault-cli cp a d/e
    Copy 'a' to 'd/e'

``vault-cli cp`` follows the ``safe-write`` parameter (see :ref:`safe-write`) and
has a ``--force`` flag, like ``vault-cli set``.

Move secrets and folders
------------------------

.. code:: console

    $ vault-cli set a b=c

    $ vault-cli mv a d/e
    Move 'a' to 'd/e'

``vault-cli mv`` follows the ``safe-write`` parameter (see :ref:`safe-write`) and
has a ``--force`` flag, like ``vault-cli set``.

Delete a secret
---------------

.. code:: console

   $ vault-cli delete d
   Done


Delete everything under blob-secret
-----------------------------------

``vault-cli delete-all`` lets you recursively delete paths. If no path is given,
all secrets are deleted (following the ``base-path`` option, see :ref:`base-path`)
By default, ``vault-cli delete-all`` will ask for confirmation for every secret.

.. code:: console

   $ vault-cli delete-all blob-secret

Use ``--force`` to bypass confirmation. Triple-check your command before you hit
``enter``.

.. code:: console

   $ vault-cli delete-all --force
