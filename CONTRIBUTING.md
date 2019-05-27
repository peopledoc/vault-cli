# Contributing

## Get in touch

If you want to help, or just to get in touch, say something in a
ticket ! We'll be in touch

## Coding in vault-cli

- Spin a configured vault (using `docker-compose`) with `./dev-env`
- Add your .vault.yml using either token, cert or userpass with:
`./dev-env auth {token|cert|userpass}`
- Have tox installed (`pip install tox` in a virtual environment)
- Format your code with `black` and `isort` (lauch `tox -e format`)
- Write tests. We currently have 100% coverage in unit test. While
this doesn't mean we're perfect (far from it), we'd like to keep
things this way. Whenever you launch the tests (`pytest`), a coverage
report will be generatedin the console and HTML. Browse it with
`firefox htmlcov/index.html`
- Check lint with `tox -e check-lint`
- The doc is part of the code too.
- If you have all the supported python versions available locally,
launch `tox`. Otherwise, don't bother, the CI will do it for you.
- Share your work as soon as possible. Don't take the risk of engaging
in a lot of work before we can be sure you're going in a direction that
is aligned with the project.
