.. _SystemD:

Integrate with SystemD
======================

Goals
-----

One of the aims of having a vault is to protect your secrets and monitor
access. This can be defeated if you copy the secrets from the vault in a
local file on the disk (especially if you don’t precisely control who
can access your file).

Additionally one of the popular methods of configuring application in
the cloud-era is through environment variables.

Vault-cli aims at helping you launch your application with the secrets
it needs without writing them on disk. This page lists a few scenarios
that may be useful.

If the value you need to pass is directly a secret that is stored in the
vault, perfect. Otherwise, you may want to create a `templated
value`__
to recreate your secret value by combining static strings and other
secrets.

.. __: https://github.com/peopledoc/vault-cli/#create-a-templated-value

Let’s assume the value you need to pass is the value you get with:

.. code:: console

   $ vault-cli get mysecret value
   ohsosecret

Passing secrets through environment
-----------------------------------

The first thing you need to figure out is if the process you’re trying
to integrate supports configuration through environment variables.

-  This may be something they tell upfront in their documentation.
-  This may be something that can be achieved through specific
   configuration tools. For example, tools that let you write
   configuration in Python files (Sentry_) or in dedicated languages like
   RainerScript (rsyslog_).
-  This maybe something that is not well documented but that still
   exists. Official docker images for the application may be using those
   variables, like for Datadog_.
-  (And in many cases, this is just not possible)

.. _Sentry: https://docs.sentry.io/server/config/
.. _rsyslog: https://www.rsyslog.com/doc/v8-stable/rainerscript/index.html
.. _Datadog: https://docs.datadoghq.com/agent/docker/?tab=standard#environment-variables

Assuming you have identified the proper enviroment variable, we will
launch the program through ``vault-cli env``. Let’s launch it as a one-off:

.. code:: console

   $ vault-cli env --envvar mysecret:value -- myprogram

This will make a variable named ``VALUE`` available to ``myprogram``.
See the :ref:`vault-cli env <vault-env>` dedicated page for more details on how you can
fine-tune the environment variable names, recursively load secrets as environment
variables etc.

Now, let’s integrate this with systemd. First, look at the existing
ExecStart command:

.. code:: console

   $ systemctl cat myprogram.service
   [Service]
   ...
   ExecStart=myprogram --options
   ...

We’ll create an override file that will change ExecStart to wrap it in
``vault-cli``:

.. code:: console

   $ sudo systemctl edit myprogram.service
   # opens a new file for edition
   [Service]
   ExecStart=
   ExecStart=vault-cli env --envvar mysecret:value=MYVAR -- myprogram --options

The empty ``ExecStart=`` tells SystemD to ignore the previous command to
launch and only launch the following one.

Save and quit the file. Load you new configuration file with:

.. code:: console

   $ sudo systemctl daemon-reload
   $ sudo systemctl restart myprogram.service

Writing secrets to files on the filesystem before start
-------------------------------------------------------

In some cases, you will need to have a file in the filesystem that
contains directly the secret. This is often the case with private keys.

Our strategy will be to mount a `RAM drive`__ when our process
start, and have our drive be accessible only for the current process.
The drive will disappear when the process terminates, and nothing will
be written on disk.

.. __: https://en.wikipedia.org/wiki/RAM_drive

In this case, we’ll also create a service override file. We'll add a wrapper
arount our program like before.

.. code:: console

   $ sudo systemctl edit myprogram.service
   # opens a new file for edition
   [Service]
   TemporaryFileSystem=/private
   ExecStart=vault-cli env --file mysecret:key=/private/path/to/secret/file -- myprogram --options

Save and quit the file. Load your new configuration file with:

.. code:: console

   $ sudo systemctl daemon-reload
   $ sudo systemctl restart myprogram.service

You will need to configure ``myprogram`` to look for your
secret file at ``/private/path/to/secret/file``.

If you need several files, you can add more ``--file`` flags, as
many times as needed.

.. note::

    If you want to use ``ssh`` within your program, and it supports reading the key from
    ``ssh-agent``, rather than writing the private key to the disk, you may want to have
    a look at the dedicated :ref:`ssh` feature.

Bake secrets into a complex configuration file
----------------------------------------------

.. warning::

   It's been reported__ that this approach doesn't work as intended. It's left
   for inspiration, but as of today, ``ExecStartPre`` cannot write to the
   private filesystem created by ``TemporaryFileSystem`` in  way that ``ExecStart``
   can later read. Please refer to the ticket for workarounds.

   .. __: https://github.com/peopledoc/vault-cli/issues/185

In some cases, the program you want to launch doesn’t accept
configuration through environment but only through configuration files.
You could be tempted to use the method above, but the configuration file
mixes secrets and a lot of other information that should not be stored
in the vault. In this case, you need a way to write your configuration
file without secrets on disk and, at the last moment, to bake the
secrets into the file. To do that we’ll use ``vault-cli template``.

See the dedicated :ref:`template` documentation for detailed use of ``vault-cli
template``.

The integration strategy will depend of several factors:

- Does``myprogram`` expect to read its configuration file at a specific location?
- Does it accept an arbitrary configuration path?
- Does the folder containing the configuration contain other
  files or just that configuration file?

We will be using a ``TemporaryFileSystem`` like above, but this option
can only be used to make a folder, not a single file. If the
configuration can be read anywhere or if the whole folder can be
overridden, then it’s the easier path. Otherwise, you may want to create
a symbolic link in place of your configuration file, that will be pointing to
your temporary file system.

Let’s assume that ``myprogram`` will read its configuration at
``/private/myprogram.conf``, through customization of the configuration file path or
through a symbolic link in the standard configuration file location.

The systemd configuration will be close to our previous case:

.. code:: console

   $ sudo systemctl edit myprogram.service
   # opens a new file for edition
   [Service]
   TemporaryFileSystem=/private
   ExecStartPre=vault-cli template --input=/etc/myprogram/myprogram.conf.j2 --output=/private/myprogram.conf

Save and quit the file. Load you new configuration file with:

.. code:: console

   $ sudo systemctl daemon-reload
   $ sudo systemctl restart myprogram.service

``vault_cli`` as a python lib
-----------------------------

Finally, if the program is made with Python and you control it, another solution can be
to use ``vault_cli`` on the Python side, and load your secrets when your process starts.
This does not follow :ref:`12-factor` methodologies, and it means your program will be
strongly coupled with the vault, which will make development more complicated.

See :ref:`library`.
