.. _vault-env:

Launch a process with your secrets as environment variables
===========================================================

See :ref:`env-vars` for reasons why you would want to pass configuration containing
secrets as environment variables.

``vault-cli`` can read secrets from the vault, turn them into environment variables and
launch the process of your choice with those environment variables. This is how it
works:

.. code:: console

    $ # Setting up a secret:
    $ vault-cli set test/my_secret value=qwerty
    Done

    $ vault-cli env --envvar test/my_secret -- bash -c 'echo $MY_SECRET_VALUE'
    qwerty

Environment variable naming
---------------------------

A path option looks like this:

.. code:: console

    $ vault-cli env --envvar [path/]{root}[:key][=prefix] [--envvar ...] -- {command...}

- The optional ``path/`` allows you to indicate the location of the secret(s) you want
  to expose. If the root begins with a `/`, the ``base-path`` option will be ignored
  (see :ref:`base-path`). This part of the path will not contribute to the environment
  variable name.
- The mandatory ``root`` element is either the name of a single secret object we want to
  expose, or the root path of a "secret directory" containing one or more secrets we
  want to expose recursively. The name of the environment variable starts with ``root``.
- If ``root`` is a path to multiple secret objects, then the relative path between
  ``root`` and each secret object will be added to the environment variable name
- For each secret object, each key of the object will become an environment variable.
  the key is added to the environment variable name.
- If the flag ``--omit-single-key`` (or the environment variable
  ``VAULT_CLI_ENV_OMIT_SINGLE_KEY``) is passed, then for each secret object, if it only
  has one key, the name of the key will not contribute to the environment variable name.
- You can limit a secret object to expose a single key by specifying ``:key``. In this
  case, the environment variable name will just be the key.
- If a ``=prefix`` is provided, it replaces the ``root`` or ``:key`` part.
- Lastly, paths such as ``--envvar ""``, ``--envvar .`` or ``--envvar =prefix`` are
  valid to express "all the secrets under``base-path``", although doing this can create
  a risk of exposing more secrets than intended. A sub-path is recommended in that case.

All parts of the secret environment variable name are uppercased, special characters
``/``, ``-`` and  `` `` (space) are changed to ``_``. If an environment variable still
contains characters that are not alphanumerical or ``_`` after this transformation, a
warning is raised, and this environment variable is skipped altogether.

Example
-------

Let's consider the vault contains only the following secret:

.. code:: console

    $ # Setting up a secret:
    $ vault-cli set a/b c=mysecret
    Done

This table maps input to output. Note that there will always be a single environment
variable and its value will always be ``mysecret``.

+---------------+-----------------------+---------------------------+
| ``--envvar``  | ``--omit-single-key`` | environment variable name |
+---------------+-----------------------+---------------------------+
| ``a``         | False                 | ``A_B_C``                 |
+---------------+-----------------------+---------------------------+
| ``a``         | True                  | ``A_B``                   |
+---------------+-----------------------+---------------------------+
| ``a=D``       | False                 | ``D_B_C``                 |
+---------------+-----------------------+---------------------------+
| ``a=D``       | True                  | ``D_B``                   |
+---------------+-----------------------+---------------------------+
| ``a/b``       | False                 | ``B_C``                   |
+---------------+-----------------------+---------------------------+
| ``a/b``       | True                  | ``B``                     |
+---------------+-----------------------+---------------------------+
| ``a/b=D``     | False                 | ``D_C``                   |
+---------------+-----------------------+---------------------------+
| ``a/b=D``     | True                  | ``D``                     |
+---------------+-----------------------+---------------------------+
| ``a/b:c``     | True or False         | ``C``                     |
+---------------+-----------------------+---------------------------+
| ``a/b:c=D``   | True or False         | ``D``                     |
+---------------+-----------------------+---------------------------+

Recommended setup
-----------------

What we recommend as the ideal setup is the following:

- Application uses a prefix for all its environment variables (say ``MYAPP``)
- All the secrets of the application are put under a common path named like the prefix
  (say ``myapp``)
- Each secret is named like its corresponding environment variable (for
  ``MYAPP_GITHUB_TOKEN`` you'll set ``myapp/github_token value=...``)
- Each secret object usually holds a single key inside, whose value is a string, and
  ``--omit-single-key`` is used
- Groups of related configuration parameters are in the same secret
  object (say you now have ``MYAPP_GITHUB_TOKEN`` and ``MYAPP_GITHUB_URL``, you'll set
  ``myapp/github token=... url=...``)

Your call would look like:

.. code:: console

    $ vault-cli env --omit-single-key --envvar myapp -- myapp

Ignoring errors
---------------

By default, ``vault-cli`` will not launch you program if an error happens during secrets
collection. You can pass ``--force`` to ensure that your program will be launched,
even if it will be missing some secrets.

.. code:: console

    $ vault-cli env --envvar myapp --force -- myapp

.. warning::

    Even if just a single key for a secret produces an error (e.g. a template rendering
    error), the whole secret will be missing.
