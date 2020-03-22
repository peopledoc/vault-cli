Have a secret reference dynamic content
=======================================

With ``vault-cli``, it's possible to have secret values be Jinja2_ templates.
This is useful if you have multiple related secrets that you with to retrieve as a
single string.

.. _Jinja2: https://jinja.palletsprojects.com/en/2.11.x/

.. note::

    This is a pure ``vault-cli`` feature, built on top of vault. Do not expect this
    to be interoperable with other vault clients.

.. warning::

    ``vault-cli`` takes the assumption that untrusted parties cannot store arbitrary
    secrets in your vault, and access those secrets, otherwise it would be trivial to
    use a templated value that would return other secrets. If you really want to use the
    vault this way, please make sure to use either the ``--no-render`` flag, the
    ``render: no`` configuration file option or the ``VAULT_CLI_RENDER=false``
    environment variable.

Create and read a templated secret
----------------------------------

Templated secrets start with the special prefix ``!template!``. Vault-cli recongizes
this and will evaluate the rest of the value as a Jinja2 template.

The template context includes a ``vault(path: str)`` function that returns the secret
object stored at path. Indivial values can be accessed by simply reading attributes on
the secret object:

.. code:: console

   $ vault set service username=foo password=bar host=example.com
   $ vault set shortcut dsn='!template!proto://{{ vault("service").username }}:{{ vault("service").password }}@{{ vault("service").host }}/'
   $ vault get shortcut dsn
   proto://foo:bar@example.com/
   $ vault --no-render get shortcut dsn
   !template!proto://{{ vault("service").username }}:{{ vault("service").password }}@{{ vault("service").host }}/

Variable rendering can be recursive as long as there is no loop (a uses b, b uses a)
