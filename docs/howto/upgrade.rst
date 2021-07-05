Upgrade ``vault-cli`` from previous version
===========================================

From 1.x to 2.x
~~~~~~~~~~~~~~~

Switch command name from ``vault`` to ``vault-cli`` if you're using it.

From 0.x to 1.x
~~~~~~~~~~~~~~~

This version includes some breaking changes about key-value mapping
management. In the previous versions of vault-cli, there was an implicit
key ``value`` that was used everywhere. The goal was to provide a path
<-> value abstraction. But it was hiding the path <-> key/value mapping
reality of vault’s kv engine.

In this release we removed the implicit ``value`` key in order to
expose a key/value mapping instead of a single value. Most of the
commands have been updated in order to add the key parameter.

A new option ``--omit-single-key`` was added to ``vault-cli env`` in order
to ignore the key when the variable names are built and there is only
one key in the mapping. This option case simplify your migration as
there won’t be an additional ``_VALUE`` suffix added to your environment
variables names.

.. note::

    Since 1.0, the official CLI name has switched from ``vault`` to ``vault-cli``
    but ``vault`` is kept for backwards compatibility. Because ``vault-cli 0.x`` was
    only compatible with the name ``vault``, the examples below are written with
    ``vault``
    After 2.0, command ``vault`` has disappeared.

The following list shows how to update your commands:

.. code:: sh

   (old) vault set path/to/creds xxx
   (new) vault set path/to/creds value=xxx

   (old) vault get path/to/creds
   (new) vault get path/to/creds value

   (old) vault env --envvar path/to/creds=FOO -- env  # FOO=xxx
   (new) vault env --envvar path/to/creds=FOO -- env  # FOO_VALUE=xxx
   (new) vault env --envvar path/to/creds:value=FOO -- env  # FOO=xxx
   (new) vault env --omit-single_key --envvar path/to/creds=FOO -- env  # FOO=xxx

The default output of ``vault get-all`` has also changed and is now flat
by default (this behavior is controlled with the ``--flat/--no-flat``
flags).

.. code:: sh

   $ vault set a/b secret=xxx
   $ vault set a/c secret=xxx
   $ vault get-all a
   ---
   a/b:
     secret: xxx
   a/c:
     secret: xxx
   $ vault get-all --no-flat a
   ---
   a:
     b:
       secret: xxx
     c:
       secret: xxx
