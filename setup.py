from setuptools import setup

setup(
    name='vault CLI',
    description='CLI tool for hashicorp vault',
    author='ylachiver',
    py_modules=['vault'],
    install_requires=[
        'requests',
        'Click',
        'pyyaml'
    ],
    entry_points=
    '''
        [console_scripts]
        vault=vault_cli.vault:cli
    ''',
    packages=[
        'vault_cli',
    ]
)

# pip install --editable .
# venv/bin/pex -v --disable-cache -o vault_cli.pex . -e vault_cli.vault:cli --python-shebang="/usr/bin/env python"
