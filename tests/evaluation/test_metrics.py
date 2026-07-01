from yslfuzz.evaluation import EvaluationMetricsCalculator
from yslfuzz.models import AttackCategory, FindingSeverity, HttpMethod
from yslfuzz.models.evaluation import ExpectedVulnerability, FindingMatch, GroundTruthLab


def test_precision_recall_and_f1_calculation() -> None:
    metrics = EvaluationMetricsCalculator().calculate(
        [
            _match("true_positive"),
            _match("false_positive", finding_id="finding_fp"),
            _match("false_negative", finding_id=None, ground_truth_id="gt_missing"),
        ],
        _report(),
        _ground_truth(),
    )

    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1_score == 0.5


def test_zero_division_metrics_return_zero_safely() -> None:
    metrics = EvaluationMetricsCalculator().calculate([], {"scan_run_id": "scan_1"}, _ground_truth())

    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0


def test_evaluation_metrics_include_endpoint_coverage_from_report() -> None:
    metrics = EvaluationMetricsCalculator().calculate([_match("true_positive")], _report(), _ground_truth())

    assert metrics.endpoint_coverage == 0.75
    assert metrics.payload_validity_rate == 0.5
    assert metrics.total_requests == 4
    assert metrics.total_payloads_generated == 3
    assert metrics.total_payloads_executed == 2
    assert metrics.findings_by_attack_category["SQL_INJECTION"] == 1


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


def _match(
    status: str,
    finding_id: str | None = "finding_1",
    ground_truth_id: str | None = "gt_1",
) -> FindingMatch:
    return FindingMatch(
        scan_run_id="scan_1",
        match_status=status,  # type: ignore[arg-type]
        finding_id=finding_id,
        ground_truth_id=ground_truth_id,
        endpoint_method=HttpMethod.GET,
        endpoint_path="/users",
        attack_category=AttackCategory.SQL_INJECTION,
        reason="test",
    )


def _report() -> dict[str, object]:
    return {
        "scan_run_id": "scan_1",
        "metrics": {
            "endpoint_coverage": 0.75,
            "payload_validity_rate": 0.5,
            "total_requests": 4,
            "findings_by_severity": {"MEDIUM": 1},
        },
        "payload_summary": {
            "generated_by_kind": {"VALID": 1, "ATTACK": 2},
            "executed_by_kind": {"VALID": 1, "ATTACK": 1},
        },
        "findings": [{"finding_id": "finding_1", "attack_category": "SQL_INJECTION"}],
    }
