Interact with a secret that starts with a dash
==============================================

Arguments starting with a dash will be interpreted as if they were command-line flags,
which can lead to all sorts of strange behaviour. Anything following a double dash
``--`` will not be seen as a flag by ``vault-cli``, even if it starts with a ``-``:

.. code:: console

   $ vault-cli set -- -secret-name -oh-so-secret=xxx
   Done

   $ vault-cli get -- -secret-name
   ---
   -oh-so-secret: xxx
