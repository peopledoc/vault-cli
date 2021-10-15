Make a secret point to dynamic content
======================================

.. warning::

    This feature will be removed from Vault-CLI in the next major version.

With ``vault-cli``, it's possible to have secret values be Jinja2_ templates. This is
useful if you have multiple related secrets that you would like to retrieve as a single
string.

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

.. note::

    Templated secrets rendering work like ``vault-cli template``. See :ref:`template`.

Create and read a templated secret
----------------------------------

Templated secrets start with the special prefix ``!template!``. Vault-cli recongizes
this and will evaluate the rest of the value as a Jinja2 template.

The template context includes a ``vault(path: str)`` function that returns the secret
object stored at path. Individual values can be accessed by simply reading attributes on
the secret object:

.. code:: console

   $ vault-cli set service username=foo password=bar host=example.com
   $ vault-cli set shortcut dsn='!template!proto://{{ vault("service").username }}:{{ vault("service").password }}@{{ vault("service").host }}/'
   $ vault-cli get shortcut dsn
   proto://foo:bar@example.com/
   $ vault-cli --no-render get shortcut dsn
   !template!proto://{{ vault("service").username }}:{{ vault("service").password }}@{{ vault("service").host }}/

Variable rendering can be recursive as long as there is no loop (a uses b, b uses a)

Including a templated secret in an Ansible YAML file
----------------------------------------------------

The following is relevant only if your setup includes Ansible_.

Ansible is based on running Jinja2 on YAML files. Consider a YAML object looking like:

.. code:: yaml

    ---
    template: !template!{{ vault("path").key }}

The ``!template`` part will be interpreted as an unknown YAML directive. The
``{{ vault("path").key }}`` will be interpreted by Ansible's Jinja2, which will crash
because Ansible doesn't have a ``vault`` function in its context.

Using ``!unsafe``, a real Ansible YAML directive this time, we can instruct Ansible
to leave the rest of the value as-is, and not run Jinja2 on it:

.. code:: yaml

    - name: Add templated secrets
      command: vault-cli set {{ item.path }} '{{ item.key }}={{ item.template }}'
      loop:
        - path: path/one
          key: mykey
          template: !unsafe '!template!{{ vault("path").key }}
        - path: path/two
          key: otherkey
          template: !unsafe '!template!{{ vault("/otherpath").somekey }}'

.. _Ansible: https://www.ansible.com/
