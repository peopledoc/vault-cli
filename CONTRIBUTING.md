# Contributing

## Get in touch

If you want to help, or just to get in touch, say something in a
ticket ! We'll be in touch

## Coding in vault-cli

1. Spin a configured vault (using `docker-compose`) with `./dev-env`
2. Have tox installed (`pip install tox` in a virtual environment)
3. Format your code with `black` and `isort` (lauch `tox -e format`)
4. Write tests. We currently have 100% coverage in unit test. While
this doesn't mean we're perfect (far from it), we'd like to keep
things this way. Whenever you launch the tests (`pytest`), a coverage
report will be generatedin the console and HTML. Browse it with
`firefox htmlcov/index.html`
5. Check lint with `tox -e check-lint`
6. The doc is part of the code too.
7. If you have all the supported python versions available locally,
launch `tox`. Otherwise, don't bother, the CI will do it for you.
8. Share your work as soon as possible. Don't take the risk of engaging
in a lot of work before we can be sure you're going in a direction that
is aligned with the project.
