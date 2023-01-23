#! /usr/bin/env python

from vault_cli.cli import main


# Shenanigans for coverage
def entrypoint(name: str):
    if name == "__main__":
        main()


entrypoint(__name__)
