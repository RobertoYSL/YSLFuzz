import csv
import json
from pathlib import Path

from yslfuzz.evaluation import EvaluationExporter
from yslfuzz.models import AttackCategory, FindingSeverity, HttpMethod
from yslfuzz.models.evaluation import (
    EvaluationMetrics,
    EvaluationReport,
    ExpectedVulnerability,
    FindingMatch,
    GroundTruthLab,
)


def test_json_evaluation_export_is_written(tmp_path: Path) -> None:
    path = EvaluationExporter().write_json(_evaluation_report(), tmp_path / "evaluation.json")

    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["metrics"]["true_positives"] == 1


def test_csv_exports_are_written_with_deterministic_headers(tmp_path: Path) -> None:
    paths = EvaluationExporter().write_all(_evaluation_report(), tmp_path, source_report=_source_report())

    assert paths["findings_csv"].exists()
    assert paths["endpoints_csv"].exists()
    assert paths["matches_csv"].exists()
    assert paths["metrics_csv"].exists()
    assert _headers(paths["findings_csv"]) == [
        "scan_run_id",
        "finding_id",
        "endpoint_method",
        "endpoint_path",
        "attack_category",
        "severity",
        "confidence",
        "detector_name",
        "affected_parameter",
        "affected_location",
        "fingerprint",
        "matched_ground_truth_id",
        "match_status",
    ]
    assert _headers(paths["metrics_csv"])[:3] == [
        "scan_run_id",
        "lab_id",
        "total_expected_vulnerabilities",
    ]


def test_evaluation_output_includes_reproducibility_metadata(tmp_path: Path) -> None:
    path = EvaluationExporter().write_json(_evaluation_report(), tmp_path / "evaluation.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["reproducibility"]["scan_run_id"] == "scan_1"
    assert data["reproducibility"]["lab_id"] == "lab_1"
    assert data["yslfuzz_version"]


def test_evaluation_output_remains_redacted(tmp_path: Path) -> None:
    report = _evaluation_report()
    report.reproducibility["raw_secret"] = "token=raw-token-value"

    path = EvaluationExporter().write_json(report, tmp_path / "evaluation.json")

    assert "raw-token-value" not in path.read_text(encoding="utf-8")


def _headers(path: Path) -> list[str]:
    with path.open(encoding="utf-8", newline="") as handle:
        return next(csv.reader(handle))


def _evaluation_report() -> EvaluationReport:
    return EvaluationReport(
        scan_run_id="scan_1",
        lab=_ground_truth(),
        metrics=EvaluationMetrics(
            scan_run_id="scan_1",
            lab_id="lab_1",
            total_expected_vulnerabilities=1,
            total_findings=1,
            true_positives=1,
            precision=1.0,
            recall=1.0,
            f1_score=1.0,
        ),
        matches=[
            FindingMatch(
                scan_run_id="scan_1",
                match_status="true_positive",
                finding_id="finding_1",
                ground_truth_id="gt_1",
                endpoint_method=HttpMethod.GET,
                endpoint_path="/users",
                attack_category=AttackCategory.SQL_INJECTION,
                expected_severity=FindingSeverity.MEDIUM,
                reason="matched",
            )
        ],
        reproducibility={"scan_run_id": "scan_1", "lab_id": "lab_1"},
    )


def _ground_truth() -> GroundTruthLab:
    return GroundTruthLab(
        lab_id="lab_1",
        lab_name="Lab",
        lab_version="0.1.0",
        target_name="target",
        target_base_url="https://api.example.test",
        api_style="REST",
        expected_vulnerabilities=[
            ExpectedVulnerability(
                ground_truth_id="gt_1",
                endpoint_path="/users",
                endpoint_method=HttpMethod.GET,
                attack_category=AttackCategory.SQL_INJECTION,
                vulnerability_type="status_code_anomaly",
                expected_severity=FindingSeverity.MEDIUM,
                description="Expected vulnerability.",
            )
        ],
    )


def _source_report() -> dict[str, object]:
    return {
        "scan_run_id": "scan_1",
        "findings": [
            {
                "finding_id": "finding_1",
                "endpoint_method": "GET",
                "endpoint_path": "/users",
                "attack_category": "SQL_INJECTION",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "detector_name": "StatusCodeAnomalyDetector",
                "affected_parameter": "name",
                "affected_location": "QUERY",
                "fingerprint_hash": "stable",
            }
        ],
        "endpoint_summary": [
            {
                "endpoint_id": "endpoint_1",
                "method": "GET",
                "path": "/users",
                "tested": True,
                "request_count": 1,
                "finding_count": 1,
                "highest_severity": "MEDIUM",
            }
        ],
    }
