Read secrets from the vault
===========================

TODO
- get
- (text or yaml)
- list
- get-all
- (flat or no-flat)


Read a secret in plain text (default)
-------------------------------------

.. code:: console

   $ vault get my_secret value
   qwerty

Read a secret in YAML format
----------------------------

.. code:: console

   $ vault get --yaml my_secret value
   --- qwerty
   ...


Get all values from the vault in a single command (yaml format)
---------------------------------------------------------------

.. code:: console

   $ vault get-all
   ---
   -secret-name:
     -oh-so-secret: xxx
   a:
     value: c
   my_other_secret:
     value: supersecret
   third_secret:
     certificate: '----BEGIN SECRET KEY----

       ...

       '

Get a nested secret based on a path
-----------------------------------

.. code:: console

   $ vault set test/my_folder_secret secret=yay
   Done

   $ vault get-all test/my_folder_secret
   ---
   test:
     my_folder_secret:
       secret: yay

   $ vault get-all --flat test/my_folder_secret
   ---
   test/my_folder_secret:
     secret: yay

Get all values recursively from several folders in a single command (yaml format)
---------------------------------------------------------------------------------

.. code:: console

   $ vault get-all test my_secret
   ---
   my_secret:
     value: qwerty
   test:
     my_folder_secret:
       secret: yay

   $ vault get-all --flat test my_secret
   ---
   my_secret:
     value: qwerty
   test/my_folder_secret:
     secret: yay
