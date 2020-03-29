#!/usr/bin/env python
"""
Usage: demo_blake2.py {payload}

Environment variables:
    DEMO_BLAKE2_AUTH_SIZE: optional
    DEMO_BLAKE2_SECRET_KEY: required
"""

import hashlib
import os
import sys


def usage() -> int:
    print(__doc__.strip())
    sys.exit(1)


def settings():
    return {
        "AUTH_SIZE": int(os.environ.get("DEMO_BLAKE2_AUTH_SIZE", 16)),
        "SECRET_KEY": os.environ.pop("DEMO_BLAKE2_SECRET_KEY"),
    }


def main(settings, payload):
    print(
        hashlib.blake2b(
            payload.encode("utf8"),
            key=settings["SECRET_KEY"].encode("utf8"),
            digest_size=settings["AUTH_SIZE"],
        ).hexdigest()
    )


if __name__ == "__main__":
    try:
        main(settings=settings(), payload=sys.argv[1])
    except (IndexError, KeyError):
        usage()
