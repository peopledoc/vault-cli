import os

import click
import yaml

from vault_cli import vault_python_api

# Ordered by increasing priority
CONFIG_FILES = [
    '/etc/vault.yml',
    '~/.vault.yml',
    './.vault.yml',
]

CONTEXT_SETTINGS = {'help_option_names': ['-h', '--help']}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
@click.option('--url', '-U', help='URL of the vault instance',
              default='https://localhost:8200')
@click.option('--verify/--no-verify', default=True,
              help='Verify HTTPS certificate')
@click.option('--certificate', '-c', type=click.File('rb'),
              help='The certificate to connect to vault')
@click.option('--token', '-t', help='The token to connect to Vault')
@click.option('--username', '-u',
              help='The username used for userpass authentication')
@click.option('--password-file', '-w', type=click.File('rb'),
              help='Can read from stdin if "-" is used as parameter')
@click.option('--base-path', '-b', help='Base path for requests')
def cli(ctx, **kwargs):
    try:
        ctx.obj = vault_python_api.VaultSession(**kwargs)
    except ValueError as exc:
        raise click.UsageError(exc)


def read_config_file(file_path):
    try:
        with open(os.path.expanduser(file_path), "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        return {}
    config.pop("config", None)

    # Because we're modifying the dict during iteration, we need to
    # consolidate the keys into a list
    for key in list(config):
        config[key.replace("-", "_")] = config.pop(key)

    _open_file(config, "certificate")
    _open_file(config, "password_file")

    return config


def _open_file(config, key):
    """
    Replace file name with open file at the given key
    in the config dict
    """
    try:
        config[key] = open(os.path.expanduser(config[key]), "rb")
    except KeyError:
        pass


@click.command("list")
@click.argument('path', required=False, default='')
@click.pass_obj
def list_(session, path):
    result = vault_python_api.list_secrets(
        session=session.session, url=session.full_url(path))
    click.echo(result)


@click.command(name='get-all')
@click.argument('path', required=False, default='')
@click.pass_obj
def get_all(session, path):
    url = session.full_url(path=path)
    result = vault_python_api.get_recursive_secrets(
        session=session.session,
        url=url)

    if result:
        click.echo(yaml.dump(result,
                             default_flow_style=False,
                             explicit_start=True))


@click.command()
@click.pass_obj
@click.option('--text', is_flag=True)
@click.argument('name', nargs=-1)
def get(session, text, name):
    result = {}
    for key in name:
        secret = vault_python_api.get_secret(session=session.session,
                                             url=session.full_url(key))
        if text:
            click.echo(secret)
            continue
        if secret:
            result[key] = secret
    if result and not text:
        click.echo(yaml.dump(result,
                             default_flow_style=False,
                             explicit_start=True))


@click.command("set")
@click.pass_obj
@click.argument('name')
@click.argument('value', nargs=-1)
def set_(session, name, value):
    if len(value) == 1:
        value = value[0]
    result = vault_python_api.put_secret(session=session.session,
                                         url=session.full_url(name),
                                         data={'value': value})
    click.echo(result)


@click.command()
@click.pass_obj
@click.argument('name')
def delete(session, name):
    result = vault_python_api.delete_secret(session=session.session,
                                            url=session.full_url(name))
    click.echo(result)


cli.add_command(get_all)
cli.add_command(get)
cli.add_command(set_)
cli.add_command(list_)
cli.add_command(delete)


def build_config_from_files():
    config = {}
    config_files = CONFIG_FILES

    for potential_file in config_files:
        config.update(read_config_file(potential_file))

    return config


def main():
    config = build_config_from_files()

    return cli(default_map=config)
