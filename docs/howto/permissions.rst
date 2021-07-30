Control permissions of newly created files
==========================================

If you want the files that ``vault-cli`` creates to have specific permissions,
use the ``--umask`` option (a value in octal base is expected):

.. code:: console

    $ vault-cli --umask=006 get -o /path/to/secret mysecret

See umask__ for more details on calculating a ``umask`` value. The default
``umask`` will be ``066``, meaning the file is readable (and writable) by the
owner only.

.. __: https://en.wikipedia.org/wiki/Umask

Quick crash course:

- The value has 3 digits that can each be 0, 2, 4 or 6
- First value controls owner permissions, second value controls group permission,
  third value controls other users permissions
- 0 is read-write, 2 is read only, 4 is write only, 6 is nothing
- "Execute" permission cannot be granted through ``umask``
