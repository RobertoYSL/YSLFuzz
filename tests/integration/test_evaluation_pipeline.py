import json
from pathlib import Path

from yslfuzz.evaluation import (
    EvaluationExporter,
    EvaluationMetricsCalculator,
    FindingMatcher,
    GroundTruthLoader,
)
from yslfuzz.models.evaluation import EvaluationReport


def test_evaluation_pipeline_from_sample_report_and_ground_truth(tmp_path: Path) -> None:
    report = _sample_report()
    ground_truth = GroundTruthLoader().load("examples/evaluation/simple_users_ground_truth.json")
    matches = FindingMatcher().match(report, ground_truth)
    metrics = EvaluationMetricsCalculator().calculate(matches, report, ground_truth)
    evaluation_report = EvaluationReport(
        scan_run_id=metrics.scan_run_id,
        lab=ground_truth,
        metrics=metrics,
        matches=matches,
        reproducibility={
            "scan_run_id": metrics.scan_run_id,
            "lab_id": ground_truth.lab_id,
            "report_schema_version": report["report_schema_version"],
        },
    )

    paths = EvaluationExporter().write_all(evaluation_report, tmp_path, source_report=report)

    assert metrics.true_positives == 1
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["metrics"]["recall"] == 1.0
    assert paths["metrics_csv"].exists()


def _sample_report() -> dict[str, object]:
    return {
        "report_schema_version": "1.0",
        "scan_run_id": "scan_1",
        "metrics": {
            "endpoint_coverage": 1.0,
            "payload_validity_rate": 0.5,
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
        },
    }
