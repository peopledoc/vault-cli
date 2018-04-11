import click
import yaml

from vault_cli import vault_python_api

CONF_FILE='test.conf'


@click.group()
@click.option('--certificate', type=click.File('rb'), help='The certificate to connect to vault')
@click.option('--token', help='The token to connect to Vault')
@click.option('--username', help='The username used for userpass authentication')
@click.option('--password-file', help='Can read from stdin if "-" is used as parameter ')
def cli(certificate, token, username, password_file):
    if token:
        vault_python_api.s.headers.update({'X-Vault-Token': token})
    elif certificate:
        vault_python_api.certificate_authentication(certificate.read())
    elif username:
        if not password_file:
            raise click.UsageError('Cannot use --username without password')
        with click.open_file(password_file) as f:
            password = f.read().strip()
        vault_python_api.userpass_authentication(username, password)


@click.command()
def list():
    r = vault_python_api.list_secrets()
    click.echo(r)


@click.command(name='get-all')
def get_all():
    r = {}
    for x in vault_python_api.list_secrets():
        v = vault_python_api.get_secret(x)
        if v:
            r[x] = v

    if r:
        click.echo(yaml.dump(r, default_flow_style=False, explicit_start=True))


@click.command()
@click.option('--text', is_flag=True)
@click.argument('name', nargs=-1)
def get(text, name):
    r = {}
    for x in name:
        v = vault_python_api.get_secret(x)
        if text:
            click.echo(v)
            continue
        if v:
            r[x] = v
    if r and not text:
        click.echo(yaml.dump(r, default_flow_style=False, explicit_start=True))


@click.command()
@click.argument('name')
@click.argument('value', nargs=-1)
def set(name, value):
    if len(value) == 1:
        value = value[0]
    r = vault_python_api.put_secret(name, {'value': value})
    click.echo(r)


@click.command()
@click.argument('name')
def delete(name):
    r = vault_python_api.delete_secret(name)
    click.echo(r)


cli.add_command(get_all)
cli.add_command(get)
cli.add_command(set)
cli.add_command(list)
cli.add_command(delete)


# File arguments
# @click.argument('input', type=click.File('rb'))
# File Path Argumments
# @click.argument('f', type=click.Path(exists=True))