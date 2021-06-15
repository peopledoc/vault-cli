``vault-cli``: 12-factor oriented command line tool for Hashicorp Vault
=======================================================================

.. image:: https://badge.fury.io/py/vault-cli.svg
    :target: https://pypi.org/pypi/vault-cli
    :alt: Deployed to PyPI

.. image:: https://readthedocs.org/projects/vault-cli/badge/?version=latest
    :target: http://vault-cli.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://github.com/peopledoc/vault-cli/workflows/CI/badge.svg
    :target: https://github.com/peopledoc/vault-cli/actions?query=workflow%3ACI
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
while following `12-factor`__ principles.

.. __: https://12factor.net/
.. _`Hashicorp Vault`: https://www.vaultproject.io/

Some features
-------------

- Configure once, use everywhere thanks to cascading (local, user, global) YAML
  configuration file
- Read, browse, write, move, delete secrets easily
- Read multiple secrets at once, as YAML
- Launch processes with your secrets as environment variables
- Launch processes with ``ssh-agent`` configured from your vault
- Write templated files with secrets inside
- Combine multiple secrets into a single one (e.g. a DSN string from components)

``vault-cli`` tries to make accessing secrets both secure and painless.

Showcase
--------

Here are a few things you might do with ``vault-cli``:

.. code-block:: console

    $ # Install:
    $ pip install vault-cli

    $ # Write a secret:
    $ vault-cli set mysecret mykey --prompt
    Please enter a value for key `mykey` of `mysecret`: *******

    $ # Read a secret:
    $ vault-cli get mysecret mykey
    ohsosecret

    $ # Load a secret into the environment variables:
    $ vault-cli env --envvar mysecret -- env | grep MYSECRET
    MYSECRET_MYKEY=ohsosecret

    $ # Load an ssh key into your ssh-agent:
    $ vault-cli ssh --key ssh_private_key -- ssh -T git@github.com
    Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.

State
-----

The package is young but supported and alive. We're mindful of deprecations through
semantic versionning and accepting bug reports and feature requests.

.. Below this line is content specific to the README that will not appear in the doc.
.. end-of-index-doc

Where to go from here
---------------------

The complete docs_ is probably the best place to learn about the project.

If you encounter a bug, or want to get in touch, you're always welcome to open a
ticket_.

.. _docs: http://vault-cli.readthedocs.io/en/latest
.. _ticket: https://github.com/peopledoc/vault-cli/issues/new
