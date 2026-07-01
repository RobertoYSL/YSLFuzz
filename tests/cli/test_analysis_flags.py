import json
import importlib
from pathlib import Path

import pytest


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")
CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


def test_scan_help_exposes_analysis_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--disable-detector" in output
    assert "--analysis-min-confidence" in output


def test_analysis_flags_are_reflected_in_report(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--dry-run",
            "--disable-detector",
            "ReflectionDetector",
            "--analysis-min-confidence",
            "MEDIUM",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["analysis_summary"]["analysis_configuration"]["disabled_detectors"] == [
        "ReflectionDetector"
    ]
    assert report["analysis_summary"]["analysis_configuration"]["minimum_confidence"] == "MEDIUM"


def test_invalid_analysis_min_confidence_fails(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "scan",
                "--openapi",
                str(EXAMPLE_SCHEMA),
                "--base-url",
                "http://localhost:8000",
                "--output",
                str(tmp_path / "report.json"),
                "--analysis-min-confidence",
                "CERTAIN",
            ]
        )

    assert exc_info.value.code == 1
