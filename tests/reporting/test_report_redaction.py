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
    ResponseRecord,
    ScanRun,
    SecurityFinding,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import JsonReporter, MarkdownReporter


def test_enriched_json_report_redacts_sensitive_values_everywhere() -> None:
    report = _report()
    encoded = JsonReporter().to_json(report)

    for raw_value in (
        "raw-authorization",
        "raw-cookie",
        "raw-password",
        "raw-token-value",
        "raw-response-cookie",
        "raw-api-key",
    ):
        assert raw_value not in encoded


def test_markdown_report_redacts_sensitive_values_everywhere() -> None:
    markdown = MarkdownReporter().to_markdown(_report())

    assert "raw-token-value" not in markdown
    assert "raw-authorization" not in markdown


def test_json_report_keeps_redaction_metadata() -> None:
    decoded = json.loads(JsonReporter().to_json(_report()))

    assert decoded["redaction_metadata"]["enabled"] is True
    assert decoded["redaction_metadata"]["sensitive_values_redacted"] is True


def _report() -> object:
    endpoint = Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="schema_1",
        name="create_user",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.POST,
    )
    request = RequestRecord(
        request_id="request_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        payload_id="payload_attack",
        method=HttpMethod.POST,
        url="https://api.example.test/users",
        headers={"Authorization": "Bearer raw-authorization", "Cookie": "session=raw-cookie"},
        body={"password": "raw-password", "name": "alice"},
    )
    response = ResponseRecord(
        response_id="response_1",
        request_id="request_1",
        status_code=500,
        headers={"Set-Cookie": "session=raw-response-cookie"},
        body_preview="token=raw-token-value",
        body_hash="hash",
    )
    payload = PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        content_type="application/json",
        generation_strategy="attack",
        seed=1,
        headers={"api_key": "raw-api-key"},
    )
    return JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        endpoints=[endpoint],
        payloads=[payload],
        requests=[request],
        responses=[response],
        findings=[_finding()],
    )


def _finding() -> SecurityFinding:
    return SecurityFinding(
        finding_id="finding_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Possible Sensitive Data Exposure",
        description="token=raw-token-value",
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        payload_id="payload_attack",
        request_ids=["request_1"],
        response_ids=["response_1"],
        evidence=[
            Evidence(
                evidence_type="sensitive_key_exposure",
                source="SensitiveDataExposureDetector",
                description="token=raw-token-value",
                request_id="request_1",
                response_id="response_1",
                observed_value_preview="token=raw-token-value",
                redacted=True,
            )
        ],
        recommendation="Remove sensitive response fields.",
        metadata={
            "detector_id": "detector_sensitive_data_exposure",
            "detector_name": "SensitiveDataExposureDetector",
            "detector_version": "0.1.0",
        },
    )
