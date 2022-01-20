from vault_cli import metadata


def test_extract_metadata():

    result = metadata.extract_metadata()
    assert result.pop("version")

    assert result == {
        "author": "PeopleDoc",
        "email": "peopledoc-python@ukg.com",
        "url": "https://github.com/peopledoc/vault-cli",
        "license": "Apache Software License",
    }
