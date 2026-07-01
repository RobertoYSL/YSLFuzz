from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ScanRun,
    SecurityFinding,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import MetricsCalculator, ReportSummaryBuilder


def test_severity_summary_counts_findings_correctly() -> None:
    summary = ReportSummaryBuilder().severity_summary(
        [_finding("finding_1", FindingSeverity.LOW), _finding("finding_2", FindingSeverity.HIGH)]
    )

    assert summary["LOW"] == 1
    assert summary["HIGH"] == 1
    assert summary["CRITICAL"] == 0


def test_confidence_summary_counts_findings_correctly() -> None:
    summary = ReportSummaryBuilder().confidence_summary(
        [
            _finding("finding_1", FindingSeverity.LOW, FindingConfidence.LOW),
            _finding("finding_2", FindingSeverity.LOW, FindingConfidence.CONFIRMED),
        ]
    )

    assert summary["LOW"] == 1
    assert summary["CONFIRMED"] == 1


def test_attack_category_summary_counts_findings_correctly() -> None:
    summary = ReportSummaryBuilder().attack_category_summary(
        [_finding("finding_1", FindingSeverity.LOW, category=AttackCategory.XSS)]
    )

    assert summary["XSS"] == 1
    assert summary["SQL_INJECTION"] == 0


def test_detector_summary_counts_findings_correctly() -> None:
    summary = ReportSummaryBuilder().detector_summary([_finding("finding_1", FindingSeverity.LOW)])

    assert summary["StatusCodeAnomalyDetector"]["finding_count"] == 1


def test_endpoint_summary_includes_tested_and_untested_endpoints() -> None:
    first = _endpoint("endpoint_1", "/users")
    second = _endpoint("endpoint_2", "/orders")

    summary = ReportSummaryBuilder().endpoint_summary(
        [first, second],
        [_request(first)],
        [_finding("finding_1", FindingSeverity.HIGH)],
    )

    assert summary[1]["endpoint_id"] == "endpoint_1"
    assert summary[1]["tested"] is True
    assert summary[1]["highest_severity"] == "HIGH"
    assert summary[0]["endpoint_id"] == "endpoint_2"
    assert summary[0]["tested"] is False


def test_payload_summary_includes_payload_counts_by_kind() -> None:
    payloads = [
        _payload("payload_valid", PayloadKind.VALID),
        _payload("payload_attack", PayloadKind.ATTACK, AttackCategory.SQL_INJECTION),
    ]
    summary = ReportSummaryBuilder().payload_summary(
        payloads,
        [_request(_endpoint("endpoint_1", "/users"), payload_id="payload_valid")],
        MetricsCalculator().calculate(scan_run_id="scan_1", payloads=payloads),
    )

    assert summary["generated_by_kind"]["VALID"] == 1
    assert summary["generated_by_kind"]["ATTACK"] == 1
    assert summary["executed_by_kind"]["VALID"] == 1
    assert summary["skipped_by_kind"]["ATTACK"] == 1


def test_analysis_summary_includes_detector_information() -> None:
    metrics = MetricsCalculator().calculate(
        scan_run_id="scan_1",
        findings=[_finding("finding_1", FindingSeverity.LOW)],
    )
    summary = ReportSummaryBuilder().analysis_summary(
        [_finding("finding_1", FindingSeverity.LOW)],
        metadata={"total_detector_results": 3, "analysis_config": {"disabled_detectors": []}},
        metrics=metrics,
        detector_metadata=[
            {
                "detector_id": "detector_status_code_anomaly",
                "name": "StatusCodeAnomalyDetector",
                "version": "0.1.0",
            }
        ],
    )

    assert summary["detector_result_count"] == 3
    assert summary["total_findings"] == 1
    assert summary["detectors"][0]["name"] == "StatusCodeAnomalyDetector"


def test_reproducibility_metadata_includes_scan_and_version() -> None:
    metadata = ReportSummaryBuilder().reproducibility_metadata(
        scan_run=ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        payloads=[_payload("payload_valid", PayloadKind.VALID)],
        findings=[],
        target=None,
        metadata={},
        generated_at=None,
        api_schema=None,
    )

    assert metadata["scan_run_id"] == "scan_1"
    assert metadata["yslfuzz_version"]


def _endpoint(endpoint_id: str, path: str) -> Endpoint:
    return Endpoint(
        endpoint_id=endpoint_id,
        api_schema_id="schema_1",
        name=path.strip("/"),
        api_style=ApiStyle.REST,
        path=path,
        method=HttpMethod.GET,
    )


def _request(endpoint: Endpoint, payload_id: str = "payload_valid") -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{endpoint.endpoint_id}",
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        payload_id=payload_id,
        method=HttpMethod.GET,
        url=f"https://api.example.test{endpoint.path}",
    )


def _payload(
    payload_id: str,
    kind: PayloadKind,
    category: AttackCategory | None = None,
) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id=payload_id,
        endpoint_id="endpoint_1",
        payload_kind=kind,
        attack_category=category,
        content_type="application/json",
        generation_strategy="test",
        seed=1,
    )


def _finding(
    finding_id: str,
    severity: FindingSeverity,
    confidence: FindingConfidence = FindingConfidence.MEDIUM,
    category: AttackCategory = AttackCategory.SQL_INJECTION,
) -> SecurityFinding:
    evidence = [
        Evidence(
            evidence_type="status_code",
            source="StatusCodeAnomalyDetector",
            description="status changed",
            request_id="request_endpoint_1",
            redacted=True,
        )
    ]
    return SecurityFinding(
        finding_id=finding_id,
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Status Code Anomaly",
        description="status changed",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        request_ids=["request_endpoint_1"],
        evidence=evidence,
        metadata={
            "detector_id": "detector_status_code_anomaly",
            "detector_name": "StatusCodeAnomalyDetector",
            "detector_version": "0.1.0",
        },
    )
