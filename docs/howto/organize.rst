Reorganize the content of the vault
===================================


Move secrets and folders
~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: console

   $ vault mv my_secret test/my_secret
   Move 'my_secret' to 'test/my_secret'

   $ vault get-all --flat
   -secret-name:
     -oh-so-secret: xxx
   a:
     value: c
   test/my_folder_secret:
     secret: yay
   test/my_secret:
     value: qwerty
   third_secret:
     certificate: '----BEGIN SECRET KEY----
       ...
       '

Delete a secret
~~~~~~~~~~~~~~~

.. code:: console

   $ vault delete my_other_secret
   Done


Delete everything under blob-secret
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: console

   $ vault delete-all blob-secret

Delete everything, no confirmation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: console

   $ vault delete-all --force
