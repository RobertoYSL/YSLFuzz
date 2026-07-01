from yslfuzz.analysis import BasicAuthorizationBypassDetector
from yslfuzz.models import (
    AttackCategory,
    FindingConfidence,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_authorization_bypass_detector_detects_suspicious_unauthenticated_success() -> None:
    results = BasicAuthorizationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200, body_hash="same"),
        _request("attack", metadata={"unauthenticated": True}),
        _response("attack", 200, body_hash="same"),
        _payload(metadata={"auth_test": "unauthenticated"}),
    )

    assert results
    assert results[0].detector_id == "detector_basic_authorization_bypass"
    assert results[0].confidence == FindingConfidence.MEDIUM
    assert results[0].evidence[0].evidence_type == "unauthorized_access"


def test_authorization_bypass_detector_does_not_trigger_without_auth_metadata() -> None:
    results = BasicAuthorizationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200, body_hash="same"),
        _request("attack"),
        _response("attack", 200, body_hash="same"),
        _payload(metadata={}, category=AttackCategory.INPUT_VALIDATION),
    )

    assert results == []


def _request(prefix: str, metadata: dict[str, object] | None = None) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        payload_id=f"payload_{prefix}",
        method=HttpMethod.GET,
        url="https://api.example.test/admin/users",
        metadata=metadata or {},
    )


def _response(prefix: str, status_code: int, body_hash: str) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_hash=body_hash,
        body_size_bytes=100,
        response_time_ms=5,
    )


def _payload(
    metadata: dict[str, object],
    category: AttackCategory = AttackCategory.BROKEN_ACCESS_CONTROL,
) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_auth",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=category,
        content_type="application/json",
        generation_strategy="attack_broken_access_control_auth_marker",
        seed=1,
        parent_payload_id="payload_valid",
        metadata=metadata,
    )
