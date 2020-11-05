Contributing
============

Get in touch
------------

If you want to help, or just to get in touch, say something in a
ticket ! We'll be in touch.

Coding in vault-cli
-------------------

Creating your development environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Clone the repository and ``cd`` to your clone. Spin a configured vault (using
``docker-compose``) with:

.. code-block:: console

    $ ./dev-env

You'll need to configure this environment in order to authenticate. Use either:

.. code-block:: console

    $ ./dev-env auth token  # Identify with a token - recommended
    $ ./dev-env auth userpass  # Identify with a username and password
    $ ./dev-env auth cert  # Identify with a certificate

Use tox for everything
^^^^^^^^^^^^^^^^^^^^^^

If you just want to run the test, linters and build the doc, you don't need
to create a virtual environment yourself. Install tox
and let it run for you: ``tox``. It will create its own environment.

.. code-block:: console

    pip install --user tox
    tox  # run everything
    tox -l  # list available environments
    tox -e format  # Run autoformatters (black & isort)
    tox -e check-lint  # Run linters
    tox -e docs  # Build documentation
    tox -e docs-spelling  # Run spellcheck on the documentation (optionnal)

Play with vault-cli locally
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install & activate your virtualenv_ the way you like. We suggest:

.. _virtualenv: https://packaging.python.org/tutorials/installing-packages/#creating-virtual-environments

.. code-block:: console

    $ python3 -m venv ~/.virtualenvs/vault-cli
    $ source ~/.virtualenvs/vault-cli/bin/activate

Install vault-cli:

.. code-block:: console

    $ pip install -r requirements.txt

.. note::

    This will also install tox in your virtual environment, which means you don't
    have to have it installed for your user, and you will still get all the
    commands listed above.

Use vault-cli:

.. code-block:: console

    $ vault-cli -h

Write tests
^^^^^^^^^^^

We currently have 100% coverage in unit test. While this doesn't mean we're perfect (far
from it), we'd like to keep things this way.

Launch all the tests in order for your current Python version with:

.. code-block:: console

    $ pytest


A coverage report will be generated in the console and HTML.
Browse it with:

.. code-block:: console

    $ python -m webbrowser file://$(pwd)/htmlcov/index.html

The rest
^^^^^^^^

Your code will be checked with linters. Some errors can be automatically fixed
by running:

.. code-block:: console

    tox -e format

All linting errors will be shown by running:

.. code-block:: console

    tox -e check-linters

The doc is part of the code too. Whenever you implement something that has a visible
effect, remember to write the doc too. That being said, if you're not comfortable
enough with writing in English, it's perfectly ok to request help in the PR.

Compile the doc with:

.. code-block:: console

    $ tox -e docs

Check the result with:

.. code-block:: console

    $ python -m webbrowser file://$(pwd)/docs/_build/html/index.html

Share your work in a Pull Request as soon as possible. Don't take the risk of engaging
in a lot of work before we can be sure you're going in a direction that is aligned with
the project. Ideally, open a ticket before doing a PR.

Don't be afraid to let the CI run everything. Unless this helps you in your goal, don't
spend too much time setting up the parts of the development environment you don't use
(all Python versions, documentation spellcheck, etc.)

Releasing
---------

Publish the current draft release from the GitHub interface and automation
will do the rest.
