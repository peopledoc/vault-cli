.. _discussions:

===========
Discussions
===========

.. contents::
  :depth: 2

Why not vault, hvac or hvac-cli?
================================

We are aware of the following "competitor" products:

- The official ``vault`` executable can be used as a ``vault`` client
- The hvac_ (*Hashicorp VAult Client*) Python library which is a wrapper around
  requests_ implementing the ``vault`` HTTP API
- The `hvac-cli`_ library
- `envconsul`_ which supports providing configuration values from consul_ and
  ``vault`` into environment variables

At its core, ``vault-cli`` want to provide:

- A simple configuration-file workflow
- Helps for :ref:`12-factor` integrations.

We felt that no tool was doing what we wanted and was accepting contribution that lead
to what we were looking for, so that why we `created our own`__.

.. __: https://xkcd.com/927/
.. _hvac: https://github.com/hvac/hvac
.. _requests: https://requests.readthedocs.io/en/master/
.. _`hvac-cli`: https://hvac-cli.readthedocs.io/en/latest/
.. _`envconsul`: https://github.com/hashicorp/envconsul
.. _consul: https://www.consul.io/

.. _`12-factor`:

12 factors
==========

`12-factor`__ applications are centered around having the
application process communicate with the outside solely through abstract and decoupled
ways, allowing concrete integration choices to vary wildly without impacting the
application code. This includes, among very different thing:

.. __: https://12factor.net/

- Reading all configuration through environment variables
- Connect to any external service using exposed configuration
- Logging through stdout
- ...

``vault-cli`` shines when used as a layer between your process manager (SystemD_,
Docker_, ...) and your application, to make your secrets accessible by your
application in a reasonably decoupled way.

.. _SystemD: https://en.wikipedia.org/wiki/Systemd
.. _Docker: https://www.docker.com/

.. _env-vars:

Environment variables
=====================

`Environment variables`_ are a set of variables provided to a process at launch time,
with the following properties:

- Environment variables names are usually uppercase ascii with underscores. Other
  characters can be supported by some operating systems, but ``vault-cli`` limits
  to this set
- Environment variables are inherited from the parent process, who has complete
  control on whether values are transmitted from its own process, removed, or if new
  values are added. By default, subprocesses inherit their parent process' whole
  environment.
- Environment variables are text only. Any other type must be parsed from text. There is
  no standard way to represent boolean values.
- Environment and the command-line string are the two main decoupled ways of
  providing context to a process. Any other way involves agreeing on a less standard
  method, including reading the file at a specific path, etc.

Because they are a standard way to give parameters to a process, environment variables
can be used by that process with zero knowledge of the deployment specifics.

That being said, there is a debate on whether using secrets for environment variables is
safe or not. Here are a few common arguments from both sides:

Pros
----

- Simple, standard
- Avoid writing secrets on disk
- OS naturally ensures that only the process user and root can read the environment of
  a running process
- When following good practice, it doesn't increase the attack surface. The risks are
  the same as with any other secret strategy

Cons
----

- Because environment variables are automatically transmitted to children processes,
  and sometimes dumped for debug purposes, putting secrets in there raises the risk of
  leaking secrets
- The information of whether the value from an environment variable is secret or not
  can be implicit in the app, leading to mishandling
- Environment can be read on Linux at ``/proc/[pid]/environ``.

Good practice to address the "Cons"
-----------------------------------

- Once a secret value is read from the environment variable, it should be removed from
  the in-memory environment. This will keep the value from being transmitted to
  children processes, dumped or sent. This does nothing to ``/proc/[pid]/environ``
  though, because this file contains the *initial* process. But if an attacker can
  access that file, they can also access the process' memory pages and read the secrets
  in the process memory directly.
- It's the application source code's role to very explicitely point our what values
  are secret. This is true when secrets are read from the environment, as well as
  from anywhere. You can tie together explicitating the secret nature of a configuration
  variable and scrubbing it from the environment.

It's no surprise that, while recognizing the value of the "Cons" argument, we think
the benefits of using secret values in environment outweight the risks.

For more information on how to use environment variables within ``vault-cli``, see
:ref:`vault-env`

.. _`Environment variables`: https://en.wikipedia.org/wiki/Environment_variable

.. _writing-to-disk:

Avoid writing secrets to the disk
=================================

Even in the era of of encrypted drives, we believe it is interesting to set the goal of
avoiding to write secrets on the disk, for multiple reasons:

- It's harder to control who reads a file than who access a ``vault``. There is no
  simple audit log allowing you to know who accessed a file.
- Writing secrets on the disk caches the information, which now exists both in the vault
  and on the disk. Cache invalidation is no easy task.
- This relies on having your disks encrypted, which is often something
  you can't control as easily as choosing the right UNIX user, group and mode.

That being said, this does apply to physical disks but not necessarily to any
filesystem. As long as proper user management is done to ensure only the right users can
access the mount, in-memory filesystems (`Ram disks`__ / tmpfs_) poses no
specific risks.

See :ref:`SystemD` for strategies on how to avoid writing on disk when your application
must read secrets from a file system.

.. __: https://en.wikipedia.org/wiki/RAM_drive
.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs

.. _secret-engines:

``kv v1`` and ``kv v2``, secret engines
=======================================

``vault`` offers several secret engines, including 2 iterations (v1 and v2) of a general
purpose key/value (kv) store.

``vault-cli`` supports ``v1`` for now, but `plans to support`__ ``v2`` in the future.

.. __: https://github.com/peopledoc/vault-cli/issues/129

`kv v2`__ adds a few interesting features:

- Versionned secrets (which help solve the rotation problem)
- Time to live, forcing you to rotate secrets regularily

.. __: https://www.vaultproject.io/docs/secrets/kv/kv-v2/#upgrading-from-version-1

``vault`` also offers a `variety`__ of secret engines, allowing
you to generate secrets in you ``vault`` directly. ``vault-cli`` currently doesn't
include specific integrations for those engines, but this is envisionned.

.. __: https://www.vaultproject.io/docs/secrets/

Secret objects and the implicit ``value`` key
=============================================

In ``vault`` and especially ``kv v1``, a secret is a JSON object (or mapping). Its
content can be any JSON value (strings, arrays, objects, ...). On the early days of
``vault-cli`` before ``1.0.0``, because most secrets were strings, a design decision had
been made to not expose the whole secret object, but only its ``value`` key. This proved
simpler for basic use-cases, but quickly turned very problematic and confusing when
working with non-``kv v1`` secret engines or with users of other vault clients.

We backed off this decision on ``1.0.0`` and made the key explicit on every subcommand.

``vault-cli env/ssh`` & UNIX signals
====================================

When using ``vault-cli env`` or ``vault-cli ssh``, ``vault-cli`` is responsible for
launching your process. You may wonder if there is a risk that ``vault-cli`` would not
forward signals correctly, which might be the case if your process was a child process
of ``vault-cli``.

Actually, ``vault-cli`` will prepare everything it needs and then use exec__, which
replace ``vault-cli``'s own process with your process, removing ``vault-cli`` from the
equation entirely. The risk is then far lower to have ``vault-cli`` cause a problem to
your process.

.. __: https://en.wikipedia.org/wiki/Exec_(system_call)

Thanks PeopleDoc
================

This project was almost entirely created by PeopleDoc employees on their
working time. Let's take this opportunity to thank PeopleDoc for funding
an Open Source project like this!

If this makes you want to know more about this company, check our website_
or our `job offerings`_ !

.. _website: https://www.people-doc.com/
.. _`job offerings`: https://www.people-doc.com/company/careers
