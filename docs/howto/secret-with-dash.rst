Interact with a secret that starts with a dash
==============================================

Sometimes, your arguments start with a dash, and ``vault-cli`` is confused because it
thinks those are command-line flags. Anything following a double dash ``--`` will not be
seen as a flag by ``vault-cli`` even if it starts with a ``-``:

.. code:: console

   $ vault set -- -secret-name -oh-so-secret=xxx
   Done

   $ vault get -- -secret-name
   ---
   -oh-so-secret: xxx
