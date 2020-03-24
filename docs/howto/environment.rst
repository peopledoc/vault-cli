.. _vault-env:

Launch a process with your secrets as  environment variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO:
- all the specifics around env var name
- including - and _
- several paths and recursive lookup
- --omit-single-key
- --

.. code:: console

   $ vault env --path test/my_secret -- env
   ...
   MY_SECRET_VALUE=qwerty
   ...
   $ vault set foo/bar/service/instance/main dsn=proto://xxx
   $ vault env --path test/my_secret:value=MYVAL --path foo/bar/service/instance/main=my -- env
   ...
   MYVAL=qwerty
   MY_DSN=proto://xxx
   ...
