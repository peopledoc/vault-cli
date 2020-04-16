Use ``vault-cli`` in your tests
===============================

A ``vault`` `pytest fixture`_ is available, but you may want to make sure that vault-cli
installs its `testing` extra dependencies:

.. _`pytest fixture`: https://docs.pytest.org/en/latest/fixture.html

.. code:: console

   $ pip install "vault-cli[testing]"

.. code:: python

   # conftest.py (for pytest)
   from vault_cli.testing import vault

   __all__ = ["vault"]

In your tests, use the ``vault`` fixture. It has a ``db`` parameter that you can use
to simulate existing secrets (keys are paths, values are secrets). When you use the
fixture, no call to a real vault will be issued, it's all in memory. Of course, this
is only meant for tests, do **NOT** use this for real-life use cases.

.. code:: python

   # test_something.py

   def test_bla(vault):
       vault.db = {"a/b": {"c": "d"}}

       assert vault.get_secret("a/b") == "c"
