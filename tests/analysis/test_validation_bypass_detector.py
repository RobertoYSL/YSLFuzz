from yslfuzz.analysis import ValidationBypassDetector
from yslfuzz.models import (
    AttackCategory,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_validation_bypass_detector_detects_invalid_payload_accepted_with_2xx() -> None:
    results = ValidationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("invalid"),
        _response("invalid", 200),
        _payload(PayloadKind.INVALID),
    )

    assert results
    assert results[0].detector_id == "detector_validation_bypass"
    assert results[0].confidence == FindingConfidence.MEDIUM
    assert results[0].severity == FindingSeverity.MEDIUM
    assert results[0].evidence[0].evidence_type == "validation_bypass"


def test_validation_bypass_detector_does_not_trigger_on_expected_4xx() -> None:
    results = ValidationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("invalid"),
        _response("invalid", 400),
        _payload(PayloadKind.INVALID),
    )

    assert results == []


def _request(prefix: str) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        payload_id=f"payload_{prefix}",
        method=HttpMethod.POST,
        url="https://api.example.test/users",
    )


def _response(prefix: str, status_code: int) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_hash="hash",
        body_size_bytes=20,
        response_time_ms=5,
    )


def _payload(kind: PayloadKind) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_invalid",
        endpoint_id="endpoint_1",
        payload_kind=kind,
        attack_category=AttackCategory.INPUT_VALIDATION,
        content_type="application/json",
        body={"name": ""},
        generation_strategy="mutation_invalid_string_empty",
        seed=1,
        parent_payload_id="payload_valid",
        metadata={"target_field": "name", "target_location": "BODY"},
    )
