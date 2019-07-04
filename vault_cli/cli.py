import contextlib
import logging
import os
from typing import Any, Dict, Mapping, NoReturn, Optional, Sequence, TextIO

import click
import yaml

import vault_cli
from vault_cli import client, environment, exceptions, settings, types

logger = logging.getLogger(__name__)

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "auto_envvar_prefix": settings.ENV_PREFIX,
}


def load_config(ctx: click.Context, param: click.Parameter, value: str) -> None:
    if value == "no":
        ctx.default_map = {}
        return

    if value is None:
        config_files = settings.CONFIG_FILES
    else:
        config_files = [value]

    config = settings.build_config_from_files(*config_files)
    ctx.default_map = config


def set_verbosity(ctx: click.Context, param: click.Parameter, value: int) -> int:
    level = settings.get_log_level(verbosity=value)
    logging.basicConfig(level=level)
    logger.info(f"Log level set to {logging.getLevelName(level)}")
    return value


@contextlib.contextmanager
def handle_errors():
    try:
        yield
    except exceptions.VaultException as exc:
        raise click.ClickException(str(exc))


def print_version(ctx, __, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"vault-cli {vault_cli.__version__}")
    click.echo(f"License: {vault_cli.__license__}")
    ctx.exit()


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
@click.option(
    "--url", "-U", help="URL of the vault instance", default=settings.DEFAULTS.url
)
@click.option(
    "--verify/--no-verify",
    default=settings.DEFAULTS.verify,
    help="Verify HTTPS certificate",
)
@click.option(
    "--ca-bundle",
    type=click.Path(),
    help="Location of the bundle containing the server certificate "
    "to check against.",
)
@click.option(
    "--login-cert",
    type=click.Path(),
    help="Path to a public client certificate to use for connecting to vault.",
)
@click.option(
    "--login-cert-key",
    type=click.Path(),
    help="Path to a private client certificate to use for connecting to vault.",
)
@click.option(
    "--token-file",
    "-T",
    type=click.Path(),
    help="File which contains the token to connect to Vault. "
    'Configuration file can also contain a "token" key.',
)
@click.option("--username", "-u", help="Username used for userpass authentication")
@click.option(
    "--password-file",
    "-w",
    type=click.Path(),
    help='Can read from stdin if "-" is used as parameter. '
    'Configuration file can also contain a "password" key.',
)
@click.option("--base-path", "-b", help="Base path for requests")
@click.option(
    "-s",
    "--safe-write/--unsafe-write",
    default=settings.DEFAULTS.safe_write,
    help="When activated, you can't overwrite a secret without "
    'passing "--force" (in commands "set", "mv", etc)',
)
@click.option(
    "--render/--no-render",
    default=settings.DEFAULTS.render,
    help="Render templated values",
)
@click.option(
    "-v",
    "--verbose",
    is_eager=True,
    callback=set_verbosity,
    count=True,
    help="Use multiple times to increase verbosity",
)
@click.option(
    "--config-file",
    is_eager=True,
    callback=load_config,
    help="Config file to use. Use 'no' to disable config file. "
    "Default value: first of " + ", ".join(settings.CONFIG_FILES),
    type=click.Path(),
)
@click.option(
    "-V",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@handle_errors()
def cli(ctx: click.Context, **kwargs) -> None:
    """
    Interact with a Vault. See subcommands for details.

    All arguments can be passed by environment variables: VAULT_CLI_UPPERCASE_NAME
    (including VAULT_CLI_PASSWORD and VAULT_CLI_TOKEN).

    """
    kwargs.pop("config_file")
    verbose = kwargs.pop("verbose")

    kwargs.update(extract_special_args(ctx.default_map, os.environ))

    # There might still be files to read, so let's do it now
    kwargs = settings.read_all_files(kwargs)
    saved_settings = kwargs.copy()
    saved_settings.update({"verbose": verbose})

    ctx.obj = client.get_client_class()(**kwargs)  # type: ignore
    ctx.obj.auth()
    ctx.obj.saved_settings = saved_settings


def extract_special_args(
    config: Mapping[str, Any], environ: Mapping[str, str]
) -> Dict[str, Any]:
    result = {}
    for key in ["password", "token"]:
        result[key] = config.get(key)
        env_var_key = "VAULT_CLI_{}".format(key.upper())
        if env_var_key in environ:
            result[key] = environ.get(env_var_key)

    return result


@cli.command("list")
@click.argument("path", required=False, default="")
@click.pass_obj
@handle_errors()
def list_(client_obj: client.VaultClientBase, path: str):
    """
    List all the secrets at the given path. Folders are listed too. If no path
    is given, list the objects at the root.
    """
    result = client_obj.list_secrets(path=path)
    click.echo("\n".join(result))


@cli.command(name="get-all")
@click.argument("path", required=False, nargs=-1)
@click.pass_obj
@handle_errors()
def get_all(client_obj: client.VaultClientBase, path: Sequence[str]):
    """
    Return multiple secrets. Return a single yaml with all the secrets located
    at the given paths. Folders are recursively explored. Without a path,
    explores all the vault.
    """
    paths = list(path) or [""]

    result = client_obj.get_all_secrets(*paths)

    click.echo(
        yaml.safe_dump(result, default_flow_style=False, explicit_start=True), nl=False
    )


@cli.command()
@click.pass_obj
@click.option(
    "--text",
    is_flag=True,
    help=(
        "--text implies --without-key. Returns the value in "
        "plain text format instead of yaml."
    ),
)
@click.argument("name")
@handle_errors()
def get(client_obj: client.VaultClientBase, text: bool, name: str):
    """
    Return a single secret value.
    """
    secret = client_obj.get_secret(path=name)
    if text:
        click.echo(secret)
        return

    click.echo(
        yaml.safe_dump(secret, default_flow_style=False, explicit_start=True), nl=False
    )


@cli.command("set")
@click.pass_obj
@click.option("--yaml", "format_yaml", is_flag=True)
@click.option("--stdin/--no-stdin", default=False)
@click.option(
    "--force/--no-force",
    "-f",
    is_flag=True,
    default=None,
    help="In case the path already holds a secret, allow overwriting it "
    "(this is necessary only if --safe-write is set).",
)
@click.argument("name")
@click.argument("value", nargs=-1)
@handle_errors()
def set_(
    client_obj: client.VaultClientBase,
    format_yaml: bool,
    stdin: bool,
    name: str,
    value: Sequence[str],
    force: Optional[bool],
):
    """
    Set a single secret to the given value(s).

    Value can be either passed as argument (several arguments will be
    interpreted as a list) or via stdin with the --stdin flag.
    """
    if stdin and value:
        raise click.UsageError("Can't set both --stdin and a value")

    final_value: types.JSONValue
    if stdin:
        final_value = click.get_text_stream("stdin").read().strip()

    elif len(value) == 1:
        final_value = value[0]

    else:
        final_value = list(value)

    if format_yaml:
        assert isinstance(final_value, str)
        final_value = yaml.safe_load(final_value)

    try:
        client_obj.set_secret(path=name, value=final_value, force=force)
    except exceptions.VaultOverwriteSecretError as exc:
        raise click.ClickException(
            f"Secret already exists at {exc.path}. Use -f to force overwriting."
        )
    except exceptions.VaultMixSecretAndFolder as exc:
        raise click.ClickException(str(exc))
    click.echo("Done")


@cli.command()
@click.pass_obj
@click.argument("name")
@handle_errors()
def delete(client_obj: client.VaultClientBase, name: str) -> None:
    """
    Delete a single secret.
    """
    client_obj.delete_secret(path=name)
    click.echo("Done")


@cli.command("env")
@click.option(
    "-p",
    "--path",
    multiple=True,
    required=True,
    help="Folder or single item. Pass several times to load multiple values. You can use --path mypath=prefix if you want to change the generated names of the environment variables",
)
@click.argument("command", nargs=-1)
@click.pass_obj
@handle_errors()
def env(
    client_obj: client.VaultClientBase, path: Sequence[str], command: Sequence[str]
) -> NoReturn:
    """
    Launch a command, loading secrets in environment.

    Strings are exported as-is, other types (including booleans, nulls, dicts, lists)
    are exported as yaml (more specifically as json).

    VARIABLE NAMES

    If the path is not a folder the prefix value is used as the name of the
    variable.
    e.g.: for a/b/key, `--path a/b/c=foo` gives `FOO=...`

    If the path is a folder, then the variable names will be generated as:
    PREFIX + _ + relative path
    e.g.: for a/b/key, `--path a/b=my` gives `MY_KEY=...`

    The standard behavior when no prefix is set will use the relative path to
    the parent of the given path as variable name
    e.g.: for a/b/key, --path a/b gives `B_KEY=...`
    e.g.: for a/b/key, --path a/b/key gives `KEY=...`
    """
    paths = list(path) or [""]

    env_secrets = {}

    for path in paths:
        path, _, prefix = path.partition("=")
        secrets = client_obj.get_secrets(path)
        env_secrets.update(
            {
                environment.make_env_key(
                    path=path, prefix=prefix, key=key
                ): environment.make_env_value(value)
                for key, value in secrets.items()
            }
        )

    environ = os.environ.copy()
    environ.update(env_secrets)

    environment.exec_command(command=command, environ=environ)


@cli.command("dump-config")
@click.pass_obj
@handle_errors()
def dump_config(client_obj: client.VaultClientBase,) -> None:
    """
    Display settings in the format of a config file.
    """
    assert client_obj.saved_settings
    click.echo(
        yaml.safe_dump(
            client_obj.saved_settings, default_flow_style=False, explicit_start=True
        ),
        nl=False,
    )


@cli.command("delete-all")
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="If not force, prompt for confirmation before each deletion.",
)
@click.argument("path", required=False, nargs=-1)
@click.pass_obj
@handle_errors()
def delete_all(
    client_obj: client.VaultClientBase, path: Sequence[str], force: bool
) -> None:
    """
    Delete multiple secrets.
    """
    paths = list(path) or [""]

    for secret in client_obj.delete_all_secrets(*paths, generator=True):
        if not force and not click.confirm(text=f"Delete '{secret}'?", default=False):
            raise click.Abort()
        click.echo(f"Deleted '{secret}'")


@cli.command()
@click.argument("source", required=True)
@click.argument("dest", required=True)
@click.option(
    "--force/--no-force",
    "-f",
    is_flag=True,
    default=None,
    help="In case the path already holds a secret, allow overwriting it "
    "(this is necessary only if --safe-write is set).",
)
@click.pass_obj
@handle_errors()
def mv(
    client_obj: client.VaultClientBase, source: str, dest: str, force: Optional[bool]
) -> None:
    """
    Recursively move secrets from source to destination path.
    """
    try:
        for old_path, new_path in client_obj.move_secrets(
            source=source, dest=dest, force=force, generator=True
        ):
            click.echo(f"Move '{old_path}' to '{new_path}'")
    except exceptions.VaultOverwriteSecretError as exc:
        raise click.ClickException(
            f"Secret already exists at {exc.path}. Use -f to force overwriting."
        )
    except exceptions.VaultMixSecretAndFolder as exc:
        raise click.ClickException(str(exc))


@cli.command()
@click.argument("template", type=click.File("r"), required=True)
@click.option(
    "-o",
    "--output",
    type=click.File("w"),
    default="-",
    help="File in which to write the rendered template. "
    "If ommited (or -), write in standard output",
)
@click.pass_obj
@handle_errors()
def template(
    client_obj: client.VaultClientBase, template: TextIO, output: TextIO
) -> None:
    """
    Render the given template and insert secrets in it.

    Rendering is done with jinja2. A vault() function is exposed that
    recieves a path and outputs the secret at this path.

    If template is -, standard input will be read.
    """
    result = client_obj.render_template(template.read())
    output.write(result)


@cli.command()
@click.pass_obj
@handle_errors()
def lookup_token(client_obj: client.VaultClientBase) -> None:
    """
    Return information regarding the current token
    """
    click.echo(
        yaml.safe_dump(
            client_obj.lookup_token(), default_flow_style=False, explicit_start=True
        ),
        nl=False,
    )


def main():
    # https://click.palletsprojects.com/en/7.x/python3/
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    os.environ.setdefault("LANG", "C.UTF-8")

    return cli()
