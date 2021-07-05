.. _ssh:

Use an SSH private key without writing it on the disk
=====================================================

Trying to use an SSH private key stored in the vault without writing it on disk (
:ref:`writing-to-disk`) can be complicated given that SSH cannot read private
keys from the environment. One standard way of reading a private key from something
else than a file is to use ``ssh-agent``.

``vault-cli ssh`` launches your process with an ``ssh-agent`` that has your key
preloaded. While the usual way of using an ``ssh-agent`` is to launch a background
process, ``ssh-agent`` can also be used on "one-shot" mode, executing a single command
and then stopping. This is what ``vault-cli ssh`` does.

.. code:: console

    $ # If your key is not passphrase-protected
    $ vault-cli ssh --key path/to/ssh_private_key:value -- ssh -T git@github.com

    $ # If your key is passphrase-protected and the passphase is in the vault
    $ vault-cli ssh \
      --key path/to/ssh_key:key \
      --passphrase path/to/ssh_key:passphrase \
      -- ssh -T git@github.com

``vault-cli ssh`` can be used with ``ssh``, but also with any program that uses ``ssh``
underneath, as long as it supports ``ssh-agent``. This includes ``git``, (which itself
includes ``pip``, ``npm`` etc.) and many others.

Combining with ``vault-cli env``
--------------------------------

If you need to have both ssh access and secrets as environment variables (see
:ref:`vault-env`), you can combine ``vault-cli env`` and ``vault-cli ssh``:

.. code:: console

    $ # If your key is not passphrase-protected
    $ vault-cli ssh --key path/to/ssh_private_key:value \
      -- vault-cli env --envvar myapp \
      -- myapp_that_needs_secrets_and_ssh
