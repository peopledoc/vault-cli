Changelog
=========

1.2.0 (2029-03-20)
-------------------

- ``vault env`` now supports ``-`` and `` `` (spaces) in variable names, changing them into ``_``
- ``vault env`` fails properly when program name is not supplied
- ``vault ssh`` lets you use SSH without writing the private key on disk
- Fix trailing slash in path issue in ``get-all`` and ``delete-all`` (#135)
- Omit secrets in ``vault env`` when path contains forbidden chars (#138)

1.1.0 (2020-02-28)
-------------------

- Add ``--output`` option to ``vault get`` (defaults to stdout)

1.0.0 (2020-02-20)
-------------------

- Added SystemD documentation (#124)
- Remove the hard-coded "value" key used in get/set (#104)
- Added ``vault env --omit-single-key`` flag to help compatibility (#104)
- Added upgrade documentation (#104)
- Enable --flat by default on ``vault get-all`` (#130)

0.13.0 (2020-02-04)
-------------------

- Fix secret whitespace stripping (#110)
- Fix vault get-all and vault env without list permission

0.12.0 (2019-10-08)
-------------------

- Add Jinja2 'include' support for template command (#116)

0.11.0 (2019-09-13)
-------------------

- Add support of templates when values are dict

0.10.0 (2019-07-30)
-------------------

- Add implicit and explicit caching (#102 / #103)
- Add ``config_file=`` in lib mode
- Add a ``--flat`` option to the ``get-all`` command (the new output uses full paths as dictionnary key)

0.9.0 (2019-07-11)
------------------

- Add a ``--prompt`` option to prompt user to fill the secret value without showing it in the history or the screen (#94).
- Can now read secrets that are not stored in a "value" key (#97)
- Sort the output of ``vault list``
- BREAKING CHANGE: Stop using ./.vault.yml as a default path (#99)

0.8.0 (2019-07-05)
------------------

- vault get defaults to text for string secrets, yaml for complex types (#87)

0.7.0 (2019-07-04)
------------------

- Add ``vault lookup-token`` (#77)
- Remove ``client.get_all()`` (after deprecation period)
- Add template values and ``--render`` features in client and cli (#65)
- Add possibility to customize environment variables names in ``vault env`` using
  ``--path path/to/keys=myprefix``
- Support absolute path (starting with /): in this case we don't prepend
  the ``base_path`` to the path parameter
- Add ``vault --version`` (#84)

0.6.0 (2019-06-15)
------------------

- Add --safe-write. 0.5.1's behaviour of not allowing overwriting without -f is not the default anymore (breaking change) (#73)
- Add certificate auth (#61)
- Remove "requests" backend and the backend argument (breaking change) (#71)
- Add testing module and pytest fixture to help external tests (#71)

0.5.1 (2019-06-06)
------------------

- Write a secret without 'read' and/or 'list' permission (#70)

0.5.0 (2019-05-28)
------------------

- Added vault mv command (#57)
- Improved README (#63)
- Added vault template (#59)

0.4.1 (2019-04-03)
------------------

- Fix 0.4.0 changelog
- Fix package python version compatibility advertising
- Make wheels for python 3 only

0.4.0 (2019-03-20)
------------------

- Added vault dump-config
- Added vault bootstrap-env
- API break : ``client.get_all(paths)`` becomes ``client.get_all_secrets(*paths)``
- Added vault delete-all
- Added context manager interface for lib usage
- Drop official support for python 2.7
- Drop unofficial support for python 3.5 (wrongly advertised as supported, see #53)
- Add support for python 3.7

0.3.9
-----

Fix Click to version 7 to avoid env precedence problem

0.3.8
-----

- Added ``--ca-bundle`` flag to specify location of CA bundle
- Environment variables when using vault_cli as lib
- Return empty list instead of crashing when listing an empty dir

0.3.7
-----

SNI compatibility is built directly into requirement environmental markers

0.3.6
-----

Added sni extras requirements for old OSes (``pip install 'vault-cli[sni]'``)

0.3.5
-----

Add flag --stdin to vault set

0.3.4
-----

- Add Jacques Rott as an author
- Configure vault_cli using environment variables

0.3.3
-----

Add ``--config-file`` option

0.3.2
-----

Fix locale issue

0.3.1
-----

Redo release

0.3.0
-----

Usable as a library too.

0.2.1
-----

* [BUGFIX] Fix Python 2 compatibility (#20)
* Created this changelog
