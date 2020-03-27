.. _safe-write:

Avoid overwriting secrets by accident
=====================================

Sometimes, you add secrets, sometimes you change existing secrets, and it can be easy
to make mistakes and overwrite an existing secret that you didn't plan to change.

In order to help you avoid this kind of mistakes, ``vault-cli`` has two operating modes:

- ``--safe-write / safe-write: yes``: writing over an existing secret will result in an
  error, except if ``--force`` is passed
- ``--unsafe-write / safe-write: no`` (default): writing over an existing secret will
  replace the secret, except if ``--no-force`` is passed

The two modes are symmetrical and allow you to choose your preferred way of handling
overwriting.

The safe or unsafe mode are meant to be activated in the configuration file and be
stable. Your scripts can then adjust the ``force`` value depending on the situation,
using command-line flags or environment variables.
