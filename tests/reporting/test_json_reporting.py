import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    ExecutionResult,
    ExecutionStatus,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    REDACTED_VALUE,
    RequestRecord,
    ResponseRecord,
    ScanRun,
    ScopeDefinition,
    SecurityFinding,
    Target,
    Evidence,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import JsonReporter, MetricsCalculator


def test_metrics_calculation_with_empty_data() -> None:
    metrics = MetricsCalculator().calculate(scan_run_id="scan_1")

    assert metrics.total_endpoints == 0
    assert metrics.tested_endpoints == 0
    assert metrics.total_requests == 0
    assert metrics.endpoint_coverage == 0.0
    assert metrics.payload_validity_rate == 0.0


def test_metrics_calculation_with_multiple_tested_and_untested_endpoints() -> None:
    first = _endpoint("endpoint_1", "/users")
    second = _endpoint("endpoint_2", "/orders")
    request = _request(first)

    metrics = MetricsCalculator().calculate(
        scan_run_id="scan_1",
        endpoints=[first, second],
        requests=[request],
    )

    assert metrics.total_endpoints == 2
    assert metrics.tested_endpoints == 1
    assert metrics.endpoint_coverage == 0.5


def test_metrics_calculation_with_successful_failed_and_timeout_results() -> None:
    first = _endpoint("endpoint_1", "/users")
    second = _endpoint("endpoint_2", "/orders")
    first_request = _request(first, request_id="request_1")
    second_request = _request(second, request_id="request_2")
    completed = ExecutionResult(
        request_id=first_request.request_id,
        response_id="response_1",
        status=ExecutionStatus.COMPLETED,
    )
    timeout = ExecutionResult(
        request_id=second_request.request_id,
        status=ExecutionStatus.FAILED,
        error_type="timeout",
    )

    metrics = MetricsCalculator().calculate(
        scan_run_id="scan_1",
        endpoints=[first, second],
        requests=[first_request, second_request],
        responses=[
            ResponseRecord(
                response_id="response_1",
                request_id=first_request.request_id,
                status_code=200,
                response_time_ms=10.0,
            ),
            ResponseRecord(
                response_id="response_2",
                request_id=second_request.request_id,
                status_code=504,
                response_time_ms=30.0,
            ),
        ],
        execution_results=[completed, timeout],
    )

    assert metrics.total_requests == 2
    assert metrics.successful_requests == 1
    assert metrics.failed_requests == 1
    assert metrics.timeout_requests == 1
    assert metrics.average_response_time_ms == 20.0


def test_payload_validity_rate_calculation() -> None:
    endpoint_id = "endpoint_1"
    valid = _payload(endpoint_id, PayloadKind.VALID)
    attack = _payload(endpoint_id, PayloadKind.ATTACK)

    metrics = MetricsCalculator().calculate(
        scan_run_id="scan_1",
        payloads=[valid, attack],
    )

    assert metrics.payloads_generated == 2
    assert metrics.valid_payloads_generated == 1
    assert metrics.attack_payloads_generated == 1
    assert metrics.payload_validity_rate == 0.5


def test_findings_are_grouped_by_severity() -> None:
    findings = [
        _finding("finding_1", FindingSeverity.LOW),
        _finding("finding_2", FindingSeverity.HIGH),
        _finding("finding_3", FindingSeverity.HIGH),
    ]

    metrics = MetricsCalculator().calculate(scan_run_id="scan_1", findings=findings)

    assert metrics.findings_total == 3
    assert metrics.findings_by_severity == {"LOW": 1, "HIGH": 2}


def test_json_report_object_creation_with_zero_findings() -> None:
    scan = _scan()
    endpoint = _endpoint("endpoint_1", "/users")
    report = JsonReporter().build_report(scan, endpoints=[endpoint], target=_target(), findings=[])

    assert report.scan_run_id == scan.scan_run_id
    assert report.metrics.total_endpoints == 1
    assert report.findings == []
    assert report.metadata["target_summary"]["name"] == "Example API"


def test_json_serialization_contains_scan_run_id_and_generated_at() -> None:
    report = JsonReporter().build_report(_scan())

    encoded = JsonReporter().to_json(report)
    decoded = json.loads(encoded)

    assert decoded["scan_run_id"] == report.scan_run_id
    assert decoded["generated_at"]
    assert decoded["report_id"].startswith("report_")
    assert decoded["redaction_enabled"] is True


def test_json_file_writing_to_temporary_path(tmp_path: Path) -> None:
    report = JsonReporter().build_report(_scan())
    output_path = tmp_path / "report.json"

    written_path = JsonReporter().write_json(report, output_path)

    assert written_path == output_path
    assert json.loads(output_path.read_text(encoding="utf-8"))["scan_run_id"] == report.scan_run_id


def test_report_redacts_authorization_cookie_and_set_cookie() -> None:
    endpoint = _endpoint("endpoint_1", "/users")
    request = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="https://api.example.test/users",
        headers={"Authorization": "Bearer raw-secret", "Cookie": "session=raw-cookie"},
    )
    response = ResponseRecord(
        request_id=request.request_id,
        status_code=200,
        headers={"Set-Cookie": "session=raw-response-cookie"},
    )

    decoded = _decoded_report(requests=[request], responses=[response])

    summary = decoded["request_response_summary"][0]
    assert summary["request"]["headers"]["Authorization"] == REDACTED_VALUE
    assert summary["request"]["headers"]["Cookie"] == REDACTED_VALUE
    assert summary["response"]["headers"]["Set-Cookie"] == REDACTED_VALUE
    assert "raw-secret" not in json.dumps(decoded)
    assert "raw-cookie" not in json.dumps(decoded)
    assert "raw-response-cookie" not in json.dumps(decoded)


def test_report_redacts_password_token_and_api_key_like_fields() -> None:
    endpoint = _endpoint("endpoint_1", "/users")
    request = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.POST,
        url="https://api.example.test/users",
        query_params={"access_token": "raw-access-token"},
        body={
            "password": "raw-password",
            "profile": {
                "api_key": "raw-api-key",
                "refresh_token": "raw-refresh-token",
                "jwt": "raw-jwt",
                "name": "alice",
            },
        },
    )

    decoded = _decoded_report(requests=[request])
    dumped = json.dumps(decoded)
    summary_request = decoded["request_response_summary"][0]["request"]

    assert summary_request["query_params"]["access_token"] == REDACTED_VALUE
    assert summary_request["body"]["password"] == REDACTED_VALUE
    assert summary_request["body"]["profile"]["api_key"] == REDACTED_VALUE
    assert summary_request["body"]["profile"]["refresh_token"] == REDACTED_VALUE
    assert summary_request["body"]["profile"]["jwt"] == REDACTED_VALUE
    assert summary_request["body"]["profile"]["name"] == "alice"
    assert "raw-password" not in dumped
    assert "raw-api-key" not in dumped
    assert "raw-access-token" not in dumped


def test_report_works_with_one_or_more_findings() -> None:
    finding = _finding("finding_1", FindingSeverity.MEDIUM)

    decoded = _decoded_report(findings=[finding])

    assert len(decoded["findings"]) == 1
    assert decoded["findings"][0]["finding_id"] == "finding_1"
    assert decoded["metrics"]["findings_total"] == 1


def test_no_external_network_calls_in_reporting_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    encoded = JsonReporter().to_json(JsonReporter().build_report(_scan()))

    assert json.loads(encoded)["scan_run_id"] == "scan_1"


def _decoded_report(
    *,
    requests: list[RequestRecord] | None = None,
    responses: list[ResponseRecord] | None = None,
    findings: list[SecurityFinding] | None = None,
) -> dict[str, Any]:
    scan = _scan()
    report = JsonReporter().build_report(
        scan,
        requests=requests or [],
        responses=responses or [],
        findings=findings or [],
    )
    decoded = json.loads(JsonReporter().to_json(report))
    assert isinstance(decoded, dict)
    return decoded


def _endpoint(endpoint_id: str, path: str) -> Endpoint:
    return Endpoint(
        endpoint_id=endpoint_id,
        api_schema_id="api_schema_1",
        name=path.strip("/") or "root",
        api_style=ApiStyle.REST,
        path=path,
        method=HttpMethod.GET,
    )


def _request(endpoint: Endpoint, request_id: str = "request_1") -> RequestRecord:
    return RequestRecord(
        request_id=request_id,
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url=f"https://api.example.test{endpoint.path}",
    )


def _payload(endpoint_id: str, payload_kind: PayloadKind) -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id=endpoint_id,
        payload_kind=payload_kind,
        attack_category=AttackCategory.INFORMATION_DISCLOSURE
        if payload_kind == PayloadKind.ATTACK
        else None,
        content_type="application/json",
        generation_strategy="unit-test",
        seed=1,
    )


def _finding(finding_id: str, severity: FindingSeverity) -> SecurityFinding:
    evidence = (
        [
            Evidence(
                evidence_type="status",
                source="response",
                description="Observed high severity signal",
                request_id="request_1",
            )
        ]
        if severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
        else []
    )
    return SecurityFinding(
        finding_id=finding_id,
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Finding",
        description="Test finding",
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        severity=severity,
        confidence=FindingConfidence.LOW,
        request_ids=["request_1"],
        evidence=evidence,
    )


def _scan() -> ScanRun:
    return ScanRun(
        scan_run_id="scan_1",
        project_id="project_1",
        target_id="target_1",
        scan_config_id="scan_config_1",
        api_schema_id="api_schema_1",
    )


def _target() -> Target:
    return Target(
        target_id="target_1",
        name="Example API",
        base_url="https://api.example.test",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTPS,
        scope=ScopeDefinition(allowed_hosts=["api.example.test"]),
    )
