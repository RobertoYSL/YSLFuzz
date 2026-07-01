import json

from yslfuzz.models import (
    ApiSchema,
    ApiStyle,
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
    SecurityFinding,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import FindingEnricher


def test_finding_enricher_adds_endpoint_path_and_method() -> None:
    enriched = _enriched()

    assert enriched[0]["endpoint_path"] == "/users"
    assert enriched[0]["endpoint_method"] == "GET"


def test_finding_enricher_adds_detector_metadata_when_available() -> None:
    enriched = _enriched()

    assert enriched[0]["detector_name"] == "StatusCodeAnomalyDetector"
    assert enriched[0]["detector_version"] == "0.1.0"


def test_finding_enricher_preserves_severity_and_confidence() -> None:
    enriched = _enriched()

    assert enriched[0]["severity"] == "MEDIUM"
    assert enriched[0]["confidence"] == "HIGH"


def test_finding_enricher_does_not_leak_secrets() -> None:
    enriched = _enriched(secret_preview="token=raw-token-value")
    encoded = json.dumps(enriched)

    assert "raw-token-value" not in encoded
    assert enriched[0]["evidence"][0]["observed_value_preview"] == "[REDACTED]"


def _enriched(secret_preview: str = "200->500") -> list[dict[str, object]]:
    endpoint = Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )
    api_schema = ApiSchema(
        api_schema_id="schema_1",
        target_id="target_1",
        api_style=ApiStyle.REST,
        base_url="https://api.example.test",
        endpoints=[endpoint],
    )
    return FindingEnricher().enrich(
        [_finding(secret_preview)],
        api_schema=api_schema,
        payloads=[_payload()],
        request_records=[
            RequestRecord(
                request_id="request_1",
                scan_run_id="scan_1",
                endpoint_id="endpoint_1",
                payload_id="payload_attack",
                method=HttpMethod.GET,
                url="https://api.example.test/users",
            )
        ],
        response_records=[
            ResponseRecord(
                response_id="response_1",
                request_id="request_1",
                status_code=500,
                body_hash="hash",
            )
        ],
        detector_metadata=[
            {
                "detector_id": "detector_status_code_anomaly",
                "name": "StatusCodeAnomalyDetector",
                "version": "0.1.0",
            }
        ],
    )


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.SQL_INJECTION,
        content_type="application/json",
        generation_strategy="attack",
        seed=7,
    )


def _finding(secret_preview: str) -> SecurityFinding:
    return SecurityFinding(
        finding_id="finding_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Status Code Anomaly",
        description="status changed",
        attack_category=AttackCategory.SQL_INJECTION,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        affected_parameter="name",
        affected_location=ParameterLocation.BODY,
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
        recommendation="Review status handling.",
        metadata={
            "detector_id": "detector_status_code_anomaly",
            "detector_name": "StatusCodeAnomalyDetector",
            "detector_version": "0.1.0",
            "fingerprint_hash": "stable-hash",
        },
    )
