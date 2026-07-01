import json

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
from yslfuzz.reporting import JsonReporter


def test_json_report_includes_report_schema_version() -> None:
    decoded = _decoded_report()

    assert decoded["report_schema_version"] == "1.0"


def test_json_report_includes_enriched_findings() -> None:
    decoded = _decoded_report()

    finding = decoded["findings"][0]
    assert decoded["enriched_findings"][0]["finding_id"] == finding["finding_id"]
    assert finding["endpoint_path"] == "/users"
    assert finding["payload_kind"] == "ATTACK"


def test_json_report_includes_summary_sections() -> None:
    decoded = _decoded_report()

    assert decoded["severity_summary"]["HIGH"] == 1
    assert decoded["confidence_summary"]["MEDIUM"] == 1
    assert decoded["attack_category_summary"]["SQL_INJECTION"] == 1
    assert decoded["detector_summary"]["StatusCodeAnomalyDetector"]["finding_count"] == 1
    assert decoded["endpoint_summary"][0]["path"] == "/users"
    assert decoded["payload_summary"]["generated_by_kind"]["ATTACK"] == 1
    assert decoded["analysis_summary"]["detector_result_count"] == 1


def test_json_report_output_ordering_is_deterministic() -> None:
    decoded = _decoded_report(
        findings=[
            _finding("finding_low", FindingSeverity.LOW, FindingConfidence.HIGH),
            _finding("finding_high", FindingSeverity.HIGH, FindingConfidence.LOW),
        ]
    )

    assert [finding["finding_id"] for finding in decoded["findings"]] == [
        "finding_high",
        "finding_low",
    ]


def test_json_report_enrichment_remains_redacted() -> None:
    encoded = json.dumps(_decoded_report(secret_preview="token=raw-token-value"))

    assert "raw-token-value" not in encoded


def _decoded_report(
    *,
    findings: list[SecurityFinding] | None = None,
    secret_preview: str = "200->500",
) -> dict[str, object]:
    endpoint = _endpoint()
    report = JsonReporter().build_report(
        _scan(),
        endpoints=[endpoint],
        payloads=[_payload()],
        requests=[_request(endpoint)],
        findings=findings or [_finding("finding_1", FindingSeverity.HIGH, secret_preview=secret_preview)],
        metadata={
            "total_detector_results": 1,
            "analysis_detectors": [
                {
                    "detector_id": "detector_status_code_anomaly",
                    "name": "StatusCodeAnomalyDetector",
                    "version": "0.1.0",
                }
            ],
        },
    )
    decoded = json.loads(JsonReporter().to_json(report))
    assert isinstance(decoded, dict)
    return decoded


def _scan() -> ScanRun:
    return ScanRun(
        scan_run_id="scan_1",
        project_id="project_1",
        target_id="target_1",
        scan_config_id="scan_config_1",
        api_schema_id="schema_1",
    )


def _endpoint() -> Endpoint:
    return Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )


def _request(endpoint: Endpoint) -> RequestRecord:
    return RequestRecord(
        request_id="request_1",
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        payload_id="payload_attack",
        method=HttpMethod.GET,
        url="https://api.example.test/users",
    )


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.SQL_INJECTION,
        content_type="application/json",
        generation_strategy="attack",
        seed=1,
    )


def _finding(
    finding_id: str,
    severity: FindingSeverity,
    confidence: FindingConfidence = FindingConfidence.MEDIUM,
    secret_preview: str = "200->500",
) -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id,
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Status Code Anomaly",
        description="status changed",
        attack_category=AttackCategory.SQL_INJECTION,
        severity=severity,
        confidence=confidence,
        payload_id="payload_attack",
        request_ids=["request_1"],
        response_ids=["response_1"],
        evidence=[
            Evidence(
                evidence_type="status_code",
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id="request_1",
                response_id="response_1",
                observed_value_preview=secret_preview,
                redacted=True,
            )
        ],
        metadata={
            "detector_id": "detector_status_code_anomaly",
            "detector_name": "StatusCodeAnomalyDetector",
            "detector_version": "0.1.0",
        },
    )
