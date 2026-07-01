import json
import importlib
from pathlib import Path

import pytest


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")
GROUND_TRUTH = Path("examples/evaluation/simple_users_ground_truth.json")


def test_evaluate_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["evaluate", "--help"])

    assert exc_info.value.code == 0
    assert "--ground-truth" in capsys.readouterr().out


def test_evaluate_command_works(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_dir = tmp_path / "eval"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")

    exit_code = CLI_MAIN.main(
        [
            "evaluate",
            "--report",
            str(report_path),
            "--ground-truth",
            str(GROUND_TRUTH),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    assert (output_dir / "evaluation.json").exists()
    assert (output_dir / "findings.csv").exists()
    assert json.loads((output_dir / "evaluation.json").read_text(encoding="utf-8"))["metrics"][
        "true_positives"
    ] == 1


def test_evaluate_command_rejects_missing_files(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "evaluate",
                "--report",
                str(tmp_path / "missing.json"),
                "--ground-truth",
                str(GROUND_TRUTH),
                "--output-dir",
                str(tmp_path / "eval"),
            ]
        )

    assert exc_info.value.code == 1


def _report() -> dict[str, object]:
    return {
        "report_schema_version": "1.0",
        "scan_run_id": "scan_1",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "metrics": {
            "endpoint_coverage": 1.0,
            "payload_validity_rate": 1.0,
            "total_requests": 2,
            "findings_by_severity": {"MEDIUM": 1},
        },
        "payload_summary": {
            "generated_by_kind": {"VALID": 1, "ATTACK": 1},
            "executed_by_kind": {"VALID": 1, "ATTACK": 1},
        },
        "endpoint_summary": [
            {
                "endpoint_id": "endpoint_1",
                "method": "GET",
                "path": "/users",
                "tested": True,
                "request_count": 2,
                "finding_count": 1,
                "highest_severity": "MEDIUM",
            }
        ],
        "findings": [
            {
                "finding_id": "finding_1",
                "endpoint_method": "GET",
                "endpoint_path": "/users",
                "attack_category": "SQL_INJECTION",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "affected_parameter": "name",
                "affected_location": "QUERY",
                "detector_name": "StatusCodeAnomalyDetector",
                "fingerprint_hash": "stable",
            }
        ],
        "reproducibility": {
            "scan_run_id": "scan_1",
            "random_seed": 1,
            "enabled_payload_modes": ["VALID", "ATTACK"],
            "attack_execution_enabled": True,
            "mutation_execution_enabled": False,
            "detectors": [{"name": "StatusCodeAnomalyDetector", "version": "0.1.0"}],
        },
    }
