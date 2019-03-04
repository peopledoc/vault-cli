from vault_cli import __main__, cli


def test_main():
    assert __main__.main == cli.main


def test_entrypoint(mocker):
    main = mocker.patch("vault_cli.__main__.main")

    __main__.entrypoint("bla")

    main.assert_not_called()

    __main__.entrypoint("__main__")

    main.assert_called()
