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

Create your Docker vault with:

.. code:: console

   $ docker run --rm --detach --name vault --port 8200:8200 -e 'VAULT_DEV_ROOT_TOKEN_ID=devtoken' -e 'SKIP_SETCAP=1' vault

.. _Docker: https://www.docker.com/

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

   $ vault -h

Create your configuration file
------------------------------



Going further
-------------

To continue with practical steps, head to the :ref:`How-to... <how-to>` section. For
example, have a look at TODO.

If you want to better understand some design decisions, head to the :ref:`discussions`
section.


.. toctree::
   :maxdepth: 2

   howto_index
   discussions
