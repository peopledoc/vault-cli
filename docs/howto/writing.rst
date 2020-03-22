Write secrets into the vault
============================

TODO
- write whole secret
- write a part
- Write by reading value from a file or stdin
- Write with secret prompt

Write a secret
~~~~~~~~~~~~~~

.. code:: console

   $ vault set my_other_secret value=supersecret
   Done

### Read/write a secret outside the base path If a base path is defined
it will be prepended to all the paths used by vault-cli except when the
paths start by a slash (``/``), those are absolute paths.

.. code:: console

   $ export VAULT_CLI_BASE_PATH=secretkvv1/myapp/
   $ vault set mysecret value=sharedsecret
   Done
   $ vault get mysecret value
   sharedsecret
   $ vault get /secretkvv1/myapp/mysecret value
   sharedsecret
   $ unset VAULT_CLI_BASE_PATH

Write a secret via stdin.
~~~~~~~~~~~~~~~~~~~~~~~~~

You can use this when the secret has multiple lines or starts with a “-”

.. code:: console

   $ vault set third_secret certificate=-
   ----BEGIN SECRET KEY----
   ...
   <hit ctrl+d to end stdin>
   Done

   vault get third_secret
   ----BEGIN SECRET KEY----
   ...

Identically, piping allows you to write the content of a file into the
vault:

.. code:: console

   $ cat my_certificate.key | vault set third_secret certificate=-
   Done

You can also load a key/value mapping in yaml or JSON format from a
file:

.. code:: console

   $ vault set third_secret --file=secret.yaml
   Done

A special value of “-” for ``--file`` means that the file is read from
stdin.


Write a secret using an invisible input prompt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This will avoid your secrets to be displayed in plain text in your shell
history.

.. code:: console

   $ vault set mypath --prompt mykey
   Please enter a value for key `mykey` of `mypath`:
   Done
