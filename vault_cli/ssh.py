import os
import subprocess
import sys
from typing import Mapping, Optional, Sequence

from vault_cli import environment as env_module
from vault_cli import exceptions

SSH_PASSPHRASE_ENVVAR = "VAULT_CLI_SSH_PASSPHRASE"


def ensure_agent() -> None:
    if "SSH_AUTH_SOCK" not in os.environ:
        wrapper_command = ["ssh-agent"] + sys.argv
        env_module.exec_command(command=wrapper_command)


def _launch_command(
    command: Sequence[str], stdin: str, environment: Mapping[str, str]
) -> str:
    environment = env_module.full_environment(environment)
    process = subprocess.run(
        command,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        encoding="utf-8",
    )
    try:
        process.check_returncode()
    except subprocess.CalledProcessError as exc:
        raise exceptions.VaultSubprocessException(process.stderr.strip()) from exc

    return process.stdout.strip()


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
