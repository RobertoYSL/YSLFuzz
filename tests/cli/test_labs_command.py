import importlib

import pytest


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


def test_labs_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["labs", "--help"])

    assert exc_info.value.code == 0
    assert "List and inspect local lab packs" in capsys.readouterr().out


def test_labs_list_works(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = CLI_MAIN.main(["labs", "list"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "simple-users" in captured.out
    assert "Simple Users Mock Lab" in captured.out


def test_labs_show_works(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = CLI_MAIN.main(["labs", "show", "--lab", "simple-users"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"lab_id": "simple-users"' in captured.out
    assert "openapi.yaml" in captured.out
