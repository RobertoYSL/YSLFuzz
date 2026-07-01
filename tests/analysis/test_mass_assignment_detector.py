from yslfuzz.analysis import MassAssignmentDetector
from yslfuzz.models import (
    AttackCategory,
    FindingConfidence,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_mass_assignment_detector_detects_controlled_extra_field_acceptance() -> None:
    results = MassAssignmentDetector().detect(
        _request("baseline"),
        _response("baseline", 200, body_hash="baseline"),
        _request("attack"),
        _response(
            "attack",
            200,
            body_preview='{"yslfuzz_probe":"mass_assignment_marker"}',
            body_hash="attack",
        ),
        _payload(metadata={"extra_fields": ["yslfuzz_probe"], "target_location": "BODY"}),
    )

    assert results
    assert results[0].detector_id == "detector_mass_assignment"
    assert results[0].confidence == FindingConfidence.MEDIUM
    assert results[0].evidence[0].evidence_type == "mass_assignment"
    assert results[0].evidence[0].model_dump(mode="json")["observed_value_preview"] == "[REDACTED]"


def test_mass_assignment_detector_does_not_overclaim_without_metadata() -> None:
    results = MassAssignmentDetector().detect(
        _request("baseline"),
        _response("baseline", 200, body_hash="baseline"),
        _request("attack"),
        _response("attack", 200, body_preview='{"yslfuzz_probe":true}', body_hash="attack"),
        _payload(metadata={}),
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


def _response(
    prefix: str,
    status_code: int,
    *,
    body_preview: str | None = None,
    body_hash: str = "hash",
) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_preview=body_preview,
        body_hash=body_hash,
        body_size_bytes=len(body_preview or "body"),
        response_time_ms=5,
    )


def _payload(metadata: dict[str, object]) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.MASS_ASSIGNMENT,
        content_type="application/json",
        body={"yslfuzz_probe": "mass_assignment_marker"},
        generation_strategy="attack_mass_assignment_extra_fields",
        seed=1,
        parent_payload_id="payload_valid",
        metadata=metadata,
    )
