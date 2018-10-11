"""
Copyright 2018 PeopleDoc
Written by Yann Lachiver
           Joachim Jablon
           Jacques Rott

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os

import click
import yaml

from vault_cli import client
from vault_cli import settings


CONTEXT_SETTINGS = {
    'help_option_names': ['-h', '--help'],
    'auto_envvar_prefix': "VAULT_CLI"
}


def load_config(ctx, param, value):
    if value == "no":
        ctx.default_map = {}
        return

    if value is None:
        config_files = settings.CONFIG_FILES
    else:
        config_files = [value]

    config = settings.build_config_from_files(*config_files)
    ctx.default_map = config


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
@click.option('--url', '-U', help='URL of the vault instance',
              default=settings.DEFAULTS['url'])
@click.option('--verify/--no-verify', default=settings.DEFAULTS['verify'],
              help='Verify HTTPS certificate')
@click.option('--certificate-file', '-c', type=click.Path(),
              help='Certificate to connect to vault. '
              'Configuration file can also contain a "certificate" key.')
@click.option('--token-file', '-T', type=click.Path(),
              help='File which contains the token to connect to Vault. '
              'Configuration file can also contain a "token" key.')
@click.option('--username', '-u',
              help='Username used for userpass authentication')
@click.option('--password-file', '-w', type=click.Path(),
              help='Can read from stdin if "-" is used as parameter. '
              'Configuration file can also contain a "password" key.')
@click.option('--base-path', '-b', help='Base path for requests')
@click.option('--backend', default=settings.DEFAULTS['backend'],
              help='Name of the backend to use (requests, hvac)')
@click.option("--config-file", is_eager=True, callback=load_config,
              help="Config file to use. Use 'no' to disable config file. "
              "Default value: first of "
              + ", ".join(settings.CONFIG_FILES), type=click.Path())
def cli(ctx, **kwargs):
    """
    Interact with a Vault. See subcommands for details.

    All arguments can be passed by environment variables: VAULT_CLI_UPPERCASE_NAME
    (including VAULT_CLI_PASSWORD and VAULT_CLI_TOKEN).

    """
    kwargs.pop("config_file")
    backend = kwargs.pop("backend")

    kwargs.update(extract_special_args(ctx.default_map, os.environ))

    # There might still be files to read, so let's do it now
    kwargs = settings.read_all_files(kwargs)
    try:
        ctx.obj = client.get_client_from_kwargs(backend=backend, **kwargs)
    except ValueError as exc:
        raise click.UsageError(str(exc))


def extract_special_args(config, environ):
    result = {}
    for key in ["password", "certificate", "token"]:
        result[key] = config.get(key)

        env_var_key = "VAULT_CLI_{}".format(key.upper())
        if env_var_key in environ:
            result[key] = environ.get(env_var_key)

    return result


@cli.command("list")
@click.argument('path', required=False, default='')
@click.pass_obj
def list_(client_obj, path):
    """
    List all the secrets at the given path. Folders are listed too. If no path
    is given, list the objects at the root.
    """
    result = client_obj.list_secrets(path=path)
    click.echo("\n".join(result))


@cli.command(name='get-all')
@click.argument('path', required=False, nargs=-1)
@click.pass_obj
def get_all(client_obj, path):
    """
    Return multiple secrets. Return a single yaml with all the secrets located
    at the given paths. Folders are recursively explored. Without a path,
    explores all the vault.
    """
    paths = path or [""]

    result = client_obj.get_all(paths)

    click.echo(yaml.safe_dump(
        result,
        default_flow_style=False,
        explicit_start=True), nl=False)


@cli.command()
@click.pass_obj
@click.option('--text',
              is_flag=True,
              help=("--text implies --without-key. Returns the value in "
                    "plain text format instead of yaml."))
@click.argument('name')
def get(client_obj, text, name):
    """
    Return a single secret value.
    """
    secret = client_obj.get_secret(path=name)
    if text:
        click.echo(secret)
        return

    click.echo(yaml.safe_dump(secret,
                              default_flow_style=False,
                              explicit_start=True), nl=False)


@cli.command("set")
@click.pass_obj
@click.option('--yaml', 'format_yaml', is_flag=True)
@click.argument('name')
@click.argument('value', nargs=-1)
def set_(client_obj, format_yaml, name, value):
    """
    Set a single secret to the given value(s).
    """
    if len(value) == 1:
        value = value[0]
    else:
        value = list(value)

    if format_yaml:
        value = yaml.safe_load(value)

    client_obj.set_secret(path=name, value=value)
    click.echo('Done')


@cli.command()
@click.pass_obj
@click.argument('name')
def delete(client_obj, name):
    """
    Deletes a single secret.
    """
    client_obj.delete_secret(path=name)
    click.echo('Done')


def main():
    # https://click.palletsprojects.com/en/7.x/python3/
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    os.environ.setdefault("LANG", "C.UTF-8")

    return cli()
