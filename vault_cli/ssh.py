import os
import subprocess
import sys
from typing import Mapping, Optional, Sequence

from vault_cli import environment as env_module

SSH_PASSPHRASE_ENVVAR = "VAULT_CLI_SSH_PASSPHRASE"


def ensure_agent() -> None:
    if "SSH_AUTH_SOCK" not in os.environ:
        wrapper_command = ["ssh-agent"] + sys.argv
        env_module.exec_command(command=wrapper_command)


def _launch_command(
    command: Sequence[str], stdin: str, environment: Mapping[str, str]
) -> str:
    environment = env_module.full_environment(environment)
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=environment
    )
    stdout, _ = process.communicate(input=stdin.encode("utf-8"))
    return stdout.decode("utf-8")


def add_key(key: str, passphrase: Optional[str] = None) -> None:
    environment = {}
    if passphrase:
        environment.update(
            {
                SSH_PASSPHRASE_ENVVAR: passphrase,
                "SSH_ASKPASS": sys.argv[0],
                "DISPLAY": ":0",
            }
        )
    _launch_command(["ssh-add", "-"], stdin=key, environment=environment)
