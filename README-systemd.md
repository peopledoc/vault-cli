# Integrate with SystemD

## Strategies

One of the aims of having a vault is to protect your secrets and monitor access. This
can be defeated if you copy the secrets from the vault in a local file on the disk
(especially if you don't precisely control who can access your file).

Additionally one of the popular methods of configuring application in the cloud-era is
through environment variables.

Vault-cli aims at helping you launch your application with the secrets it needs without
writing them on disk. This page lists a few scenario that may be useful.

If the value you need to pass is directly a secret that is stored in the vault, perfect.
Otherwise, you may want to create a [templated
value](https://github.com/peopledoc/vault-cli/#create-a-templated-value) to recreate
your secret value by combining static strings and other secrets.

Let's assume the value you need to pass is the value you get with:

```console
$ vault get mysecret value
ohsosecret
```

## ``vault env``

The first thing you need to figure out is if the process you're trying to integrate
supports configuration through environment variables.

- This may be something they tell upfront in their documentation.
- This may be something that can be achieved through specific configuration tools. For
  example, tools that let you write configuration in Python files (Sentry) or in
  dedicated languages like RainerScript (rsyslog).
- This maybe something that is not well documented but that still exist. Official docker
  images for the application may be using those variables
- (And in many cases, this is just not possible)

Assuming you have identified the proper enviroment variable, we will launch the program
through ``vault env``. Let's launch it as a one-off:

```console
$ vault env --path mysecret:value -- myprogram
```

This will make a variable named ``MYSECRET`` available to ``myprogram``. If you need the
environment variable to have a specific name (e.g. ``MYVAR``), you can use:

```console
$ vault env --path mysecret:value=MYVAR -- myprogram
```

We could check that it works as expected by launching `env` instead of `myprogram`.
`env` lists all environment variables.

```console
$ vault env --path mysecret:value=MYVAR -- env |grep MYVAR
```

If you need so, vault-env can load several secrets by specifying the ``--path`` option
more than once. If the path corresponds to a "folder", all secrets beneath that path
will be recursively added as environment variables, through their names.

Now, let's integrate this with systemd. First, look at the existing execstart command:

```console
$ systemctl cat myprogram.service
[Service]
...
ExecStart=myprogram --options
...
```

We'll create an override file that will change ExecStart to wrap it in vault cli:

```console
$ sudo systemctl edit myprogram.service
# opens a new file for edition. Type the following, adapting your needs:
[Service]
ExecStart=
ExecStart=vault env --path mysecret:value=MYVAR -- myprogram --options
```

The empty `ExecStart=` tells SystemD to ignore the previous command to launch and only
launch to following one.

Save and quit the file. Load you new configuration file with:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl restart myprogram.service
```

## ``vault get --output``

In some cases, you will need to have a file in the filesystem that contains directly
the secret. This is often the case with private keys.

Our strategy will be to mount a [RAM drive](https://en.wikipedia.org/wiki/RAM_drive)
when our process start, and have our drive be accessible only for the current process.
The drive will disappear when the process terminates, and nothing will be written on
disk.

In this case, we'll also create a service override file, but this time, we will be
adding a command that launches before or main command:

```console
$ sudo systemctl edit myprogram.service
# opens a new file for edition. Type the following, adapting your needs:
[Service]
TemporaryFileSystem=/private
ExecStartPre=vault get mysecret --output=/private/path/to/secret/file
```

Save and quit the file. Load you new configuration file with:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl restart myprogram.service
```

Of course, you will need to configure ``myprogram`` to look for your secret file at
``/private/path/to/secret/file``.

If you need several files, you can repeat the `ExecStartPre` line as many times as
needed.


## ``vault template``

In some cases, the program you want to launch doesn't accept configuration through
environment but only through configuration files. You could be tempted to use the method
above, but the configuration file mixes secrets and a lot of other information that
should not be stored in the vault. In this case, you need a way to write your
configuration file without secrets on disk and, at the last moment, to bake the secrets
into the file. To do that we'll use ``vault template``.

Assuming this would be your file:

```
# /etc/myprogram/myprogram.conf
[myprogram]
url=http://example.com
token=mytoken
```

Then the first step will be to produce a template for this file without the secret:
```
# /etc/myprogram/myprogram.conf.j2
[myprogram]
url=http://example.com
token={{ vault("mysecret").value }}
```

The rest depends on whether ``myprogram`` expects to read its configuration file at a
specific location or if it can accept an arbitrary configuration path, and whether the
folder containing the configuration contains other files or juste that file.

We will be using a ``TemporaryFileSystem`` like above, but this option can only be used
to make a folder, not a single file. If the configuration can be read anywhere or if
the whole folder can be overridden, then it's the easier path. Otherwise, you may want
to create a simlink in place of your configuration file, that will be pointing to your
temporary file system.

Let's assume that through configuration or through a symlink, ``myprogram`` will read
its configuration at ``/private/myprogram.conf``.

The systemd configuration will be close to our previous case:

```console
$ sudo systemctl edit myprogram.service
# opens a new file for edition. Type the following, adapting your needs:
[Service]
TemporaryFileSystem=/private
ExecStartPre=vault template --input=/etc/myprogram/myprogram.conf.j2 --output=/private/myprogram.conf
```

Save and quit the file. Load you new configuration file with:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl restart myprogram.service
```

## ``vault_cli`` as a python lib

Finally, if the program is made with Python and you control it, another solution
can be to use ``vault_cli`` on the Python side, and load your secrets when your process
starts. This is not very [12-factor-ish](https://12factor.net/config), and it means your
program will be strongly coupled with the vault, which wouldn't be ideal, but sometimes,
ideal just doesn't exist.

*TODO: document usage of vault_cli as a lib*
