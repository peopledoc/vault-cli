``vault-cli``: 12-factor oriented command line tool for Hashicorp Vault
=======================================================================

.. image:: https://badge.fury.io/py/vault-cli.svg
    :target: https://pypi.org/pypi/vault-cli
    :alt: Deployed to PyPI

.. image:: https://readthedocs.org/projects/vault-cli/badge/?version=latest
    :target: http://vault-cli.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://travis-ci.org/peopledoc/vault-cli.svg?branch=master
    :target: https://travis-ci.org/peopledoc/vault-cli
    :alt: Continuous Integration Status

.. image:: https://codecov.io/gh/peopledoc/vault-cli/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/peopledoc/vault-cli
    :alt: Coverage Status

.. image:: https://img.shields.io/badge/License-Apache-green.svg
    :target: https://github.com/peopledoc/vault-cli/blob/master/LICENSE
    :alt: Apache License

.. image:: https://img.shields.io/badge/Contributor%20Covenant-v1.4%20adopted-ff69b4.svg
    :target: https://github.com/peopledoc/vault-cli/blob/master/CODE_OF_CONDUCT.md
    :alt: Contributor Covenant

``vault-cli`` is a Python 3.6+ tool that offers simple interactions to manipulate
secrets from `Hashicorp Vault`_. With ``vault-cli``, your secrets can be kept secret,
while following `12-factor`_ principles.

.. _`Hashicorp Vault`: https://www.vaultproject.io/
.. _`12-factor`: https://12factor.net/

Some features
-------------

- Cascading (local, user, global) YAML configuration file: configure once, use
  everywhere,
- Read, browse, write, move, delete secrets easily,
- Read multiple secrets at once, as YAML,
- Launch processes with your secrets as environment variables,
- Launch processes with ``ssh-agent`` cofigured from your vault,
- Write templated files with secrets inside,
- Combine multiple secrets into a single one (e.g. a DSN string from components).

``vault-cli`` tries to make accessing secrets both secure and painless.

Showcase
--------

Here's a few things you might do with ``vault-cli``:

.. code-block:: console

    $ # Install:
    $ pip install vault-cli

    $ # Write a secret:
    $ vault set mysecret mykey --prompt
    Please enter a value for key `mykey` of `mysecret`: *******

    $ # Read a secret:
    $ vault get mysecret mykey
    ohsosecret

    $ # Load a secret into the environment variables:
    $ vault env --path mysecret -- env | grep MYSECRET
    MYSECRET_MYKEY=ohsosecret

    $ # Load a ssh key into your ssh-agent:
    $ vault ssh --key ssh_private_key -- ssh -T git@github.com
    Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.

State
-----

The package is young but supported, alive, we're mindful of deprecations through
semantic versionning, and accepting bug reports and feature requests.

.. Below this line is content specific to the README that will not appear in the doc.
.. end-of-index-doc

Where to go from here
---------------------

The complete docs_ is probably the best place to learn about the project.

If you encounter a bug, or want to get in touch, you're always welcome to open a
ticket_.

.. _docs: http://vault-cli.readthedocs.io/en/latest
.. _ticket: https://github.com/peopledoc/vault-cli/issues/new
