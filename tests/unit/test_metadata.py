import re

from vault_cli import metadata


def test_extract_metadata():

    result = metadata.extract_metadata()
    assert re.match(r"\d+\.\d+\.\d+(\.dev0)?", result.pop("version"))

    assert result == {
        "author": "PeopleDoc",
        "email": "joachim.jablon@people-doc.com",
        "url": "https://github.com/peopledoc/vault-cli",
        "license": "Apache Software License",
    }
