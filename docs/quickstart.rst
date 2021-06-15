Quickstart
==========

Prerequisites
-------------

This tutorial will work with Linux and Mac OS. It is untested with Windows.
We'll be using:

- Docker_ (optionally)
- Python3 (3.6 or over)

We'll place ourselves in an empty directory:

.. code:: console

    $ mkdir vault-cli-demo
    $ cd vault-cli-demo

Having your vault ready
-----------------------

You can follow this tutorial with your own vault if you have one. We'll show you how
to make a development vault with Docker_. Be aware that this vault is not suitable for
holding real secrets.

Create your `Docker vault`_ with:

.. code:: console

    $ docker run \
        --rm --detach --name vault --port 8200:8200 \
        -e 'VAULT_DEV_ROOT_TOKEN_ID=devtoken' \
        -e 'SKIP_SETCAP=1' vault

.. note::

    A Docker container launched this way will be automatically removed when it stops
    (``--rm``). Also, it will be launched in background (``--detach``). In order to
    check if it's still alive, use ``docker ps``. For logs, use ``docker logs vault``.
    To stop it, use ``docker stop vault``. To launch it again, re-execute the command
    above.

.. _Docker: https://www.docker.com/
.. _`Docker vault`: https://hub.docker.com/_/vault

Install vault-cli
-----------------

Create a `virtual environment`__, and activate it. Install ``vault-cli``:

.. __: https://packaging.python.org/tutorials/installing-packages/#creating-virtual-environments

.. code:: console

    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install vault-cli

Check your installation with:

.. code:: console

    $ vault-cli -h
    Usage: vault [OPTIONS] COMMAND [ARGS]...
    ...

Create your configuration file
------------------------------

If you're using the Docker vault we created earlier, then all default parameters would
be correct, and you'll just need a token. If you're using you own vault, please
refer to the configuration documentation: :ref:`configure`.

``vault-cli`` can be configured by several ways, including environment variables and
YAML configuration file. We'll take the easiest path here, and just export an
environment variable with our token. In a real case, you may want to use a more
persistent method, like the configuration file. It all depends how you want to secure
the vault credentials.

.. code:: console

    $ export VAULT_CLI_TOKEN=devtoken

.. note::

    This variable will only be defined in your current terminal. If you close
    your terminal at some point during the tutorial, you'll need to execute this again.

**We're finally ready! Yay!**

Writing things in the vault
---------------------------

The vault contains secret objects, which are JSON objects (as in ``{"key": "value"}``)
stored at specific paths. ``vault-cli`` lets us write string values for specific keys at
a specific path easily:

.. code:: console

    $ vault-cli set demo/blake2 secret_key=du9dibieNg3lei0teidal9
    Done

We can also build more complex objects. ``vault-cli`` can be passed the whole secret
object instead of just a key/value with the flag ``--file``. Also, ``vault-cli`` can
read its input from the standard input with the special value ``-``.

``vault-cli`` expects YAML for input, and JSON is a subset of YAML, so we'll use JSON.

.. code:: console

    $ echo \
        '{"Mizaru": "see no evil",' \
        ' "Kikazaru": "hear no evil",' \
        ' "Iwazaru": "speak no evil"}' | \
        vault-cli set wise_monkeys --file=-
    Done

Read from the vault
-------------------

Similarily, you can read a single value from the vault:

.. code:: console

    $ vault-cli get demo/blake2 secret_key
    du9dibieNg3lei0teidal9

Or you can read a whole secret object at once, and receive YAML:

.. code:: console

    $ vault-cli get wise_monkeys
    ---
    Iwazaru: speak no evil
    Kikazaru: hear no evil
    Mizaru: see no evil

You can also read multiple paths at once, recursively:

.. code:: console

    $ vault-cli get-all
    ---
    demo/blake2:
      secret_key: du9dibieNg3lei0teidal9
    wise_monkeys:
      Iwazaru: speak no evil
      Kikazaru: hear no evil
      Mizaru: see no evil

**And now, let's use vault-cli with an app!**

Creating the app
----------------

We're going to try and make a basic CLI application that will hash a payload using
Blake2_. That's not going to be the most elaborate application, but we should be able to
showcase a standard ``vault-cli`` integration.

Here's our application. We'll write it in ``quickstart_demo.py``.

.. literalinclude:: quickstart_demo.py

.. _Blake2: https://en.wikipedia.org/wiki/BLAKE_(hash_function)

Let's look at the important parts.

Settings
~~~~~~~~

.. literalinclude:: quickstart_demo.py
   :pyobject: settings

We're defining our settings, reading all the values from the environment.

.. note::

    Normal values are read as-is, but secret values are removed from environment as
    they're being read. Please refer to :ref:`env-vars` for explanation.

Main
~~~~

.. literalinclude:: quickstart_demo.py
   :pyobject: main

This is the core of the "app". We're using our settings without caring about their
origin. It's important to have the application be decoupled from its configuration.

Launching it as-is should result in an error, because the secret key environment
variable is undefined:

.. code:: console

    ./quickstart_hmac.py my_payload
    Usage: demo_blake2.py encode {payload}

    Environment variable DEMO_BLAKE2_SECRET_KEY is required.

Passing environment variables from the vault to our program
-----------------------------------------------------------

``vault-cli env`` will let us describe the secrets we want from the vault, how to turn
them into environment variables and the program we want to launch.

Let's try it. First we'll launch the command ``env``, which prints the environment.

.. code:: console

    $ vault-cli env --envvar demo -- env | tail -1
    DEMO_BLAKE2_SECRET_KEY=du9dibieNg3lei0teidal9

As you can see, the secrets (or, here, the secret) under the path ``demo`` have been
extracted into an environment variable, named after its path, and the key of the secret
in the secret object.

.. note::

    In our example, the environment variable name and the location of secrets in the
    vault have been chosen to match. This doesn't have to be the case, you have quite a
    few knobs you can control to help you get a good match between your vault
    organization and the environment variables expected by your application. See
    :ref:`vault-env`.

.. note::

    The ``--`` argument lets us distinguish between the vault-cli arguments and our
    own command's arguments. Even when we don't have arguments, it's a good idea to
    always include it for readability.

.. note::

    The ``| tail -1`` will extract the last line from the output to help us find our
    environment variable more easily. It's for display purposes, and entirely optional.

Ok, now for the real thing:

.. code:: console

    $ vault-cli env --envvar demo -- ./docs/quickstart_demo.py yay
    341c93333a9df726c57671891d6bbea1

**Yay!**

We now have an executable command that will launch our app with all the necessary
secrets. Notice how we managed to do this without writing a single secret to our disk,
and without modifying the application to be integrated to the vault.

**Thank you!** for tuning it and following this tutorial, we hope you'll love
discovering the rest of ``vault-cli`` (there's a lot more to see!).

Going further
-------------

To continue with practical steps, head to the :ref:`how-to` section.
We highly recommend you have a look at the SystemD integration section, even if you
don't use SystemD, for inspiration. See :ref:`SystemD`.

If you want to better understand some design decisions, head to the :ref:`discussions`
section.

.. toctree::
    :maxdepth: 2

    howto_index
    discussions
