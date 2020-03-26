.. _template:

Write templated files
=====================

TODO

.. code:: console

   $ vault set my_secret username=John password=qwerty
   Done

   $ vault template mytemplate.j2 > /etc/conf

   # mytemplate.j2:
   User={{ vault("my_secret").username }}
   Password={{ vault("my_secret").password }}

   # /etc/conf:
   User=John
   Password=qwerty

(Use ``-`` for stdin and ``-o <file or ->`` to specify the file to write
to, or stdout).
