.. _template:

Render templated files with secrets
===================================

Sometimes, you need to write a configuration file that contains secrets. That what
``vault-cli template`` is for. This command lets you write Jinja2_ templates and
have vault render them, replacing calls to ``vault()`` by the corresponding
secrets.

.. _Jinja2: https://jinja.palletsprojects.com/en/2.11.x/

.. warning::

    Ideally, it's best to avoid writing secrets to the disk (see
    :ref:`writing-to-disk`). This command can still be useful, but consider coupling it
    with ways to write on ephemeral storage, and check your umask__ and the permissions
    of the created file. See :ref:`SystemD` for safe integration strategies.

.. __: https://en.wikipedia.org/wiki/Umask

We'll consider that your vault has been setup with
the following secret:

.. code:: console

    $ vault-cli set myapp token=mysecrettoken

Create your template using Jinja2, indicating where you want to inject secrets and
which secrets by editing e.g. ``/etc/myapp.conf.j2``::

    [myapp]
    url = http://example.com
    token = {{ vault("myapp").token }}

Render your template:

.. code:: console

    $ vault-cli template /etc/myapp.conf.j2 --output /etc/myapp.conf
    $ cat /etc/myapp.conf
    [myapp]
    url = http://example.com
    token = mysecrettoken

If output file is not specified or ``-``, ``stdin`` will be used.

Writing template files with ansible
-----------------------------------

The following is relevant only if your setup includes Ansible_.

.. _Ansible: https://www.ansible.com/

If you write your template using Ansible, you will need a way to instruct it not to
try rendering the Jinja2 instructions that are meant for ``vault-cli`` to process.
There are two classic ways for doing this:

- If your template doesn't need Ansible-level Jinja2 rendering, make sure you
  write it with a ``file:`` task and not a ``template:`` task. To make things
  clearer, in your playbook or role, store the template in the ``files`` directory
  and not in the ``templates`` directory.
- If you need both Ansible-level and ``vault-cli``-level Jinja2 rendering, you'll
  need to escape the ``vault-cli`` Jinja2 directives::

    [myapp]
    url = {{ myapp_url }}  # Ansible rendering
    token = {{ '{{ vault("myapp").token }}' }}  # vault-cli
    {# Or: #}
    token = {{ '{{' }}  vault("myapp").token {{ '}}' }}  # vault-cli
