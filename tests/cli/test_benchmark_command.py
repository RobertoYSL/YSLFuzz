import importlib
import json
from pathlib import Path

import pytest


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")
EXAMPLE_CONFIG = Path("examples/benchmarks/simple_users_benchmark.json")


def test_benchmark_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["benchmark", "--help"])

    assert exc_info.value.code == 0
    assert "--config" in capsys.readouterr().out


def test_benchmark_requires_config_and_output_dir(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["benchmark"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "--config" in captured.err
    assert "--output-dir" in captured.err


def test_benchmark_fails_on_existing_output_dir_without_overwrite(tmp_path: Path) -> None:
    output_dir = tmp_path / "benchmark"
    output_dir.mkdir()

    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "benchmark",
                "--config",
                str(EXAMPLE_CONFIG),
                "--output-dir",
                str(output_dir),
            ]
        )

    assert exc_info.value.code == 1


def test_benchmark_command_works_with_example_config(tmp_path: Path) -> None:
    output_dir = tmp_path / "benchmark"

    exit_code = CLI_MAIN.main(
        [
            "benchmark",
            "--config",
            str(EXAMPLE_CONFIG),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    assert (output_dir / "benchmark_manifest.json").exists()
    assert (output_dir / "benchmark_summary.csv").exists()
    assert (output_dir / "jobs" / "simple_users_dry_run" / "scan_report.json").exists()
    assert (
        output_dir
        / "jobs"
        / "simple_users_dry_run"
        / "evaluation"
        / "evaluation_report.json"
    ).exists()
    summary = json.loads((output_dir / "benchmark_summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"


def test_benchmark_overwrite_allows_existing_output_dir(tmp_path: Path) -> None:
    output_dir = tmp_path / "benchmark"
    output_dir.mkdir()

    exit_code = CLI_MAIN.main(
        [
            "benchmark",
            "--config",
            str(EXAMPLE_CONFIG),
            "--output-dir",
            str(output_dir),
            "--overwrite",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "benchmark_manifest.json").exists()
