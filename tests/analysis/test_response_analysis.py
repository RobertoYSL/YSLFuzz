from yslfuzz.analysis import AnalysisEngine, FindingBuilder, ReflectionDetector
from yslfuzz.models import (
    AttackCategory,
    DetectorResult,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_analysis_engine_produces_detector_results() -> None:
    detector_results, findings = AnalysisEngine(detectors=[ReflectionDetector()]).analyze(
        _request("baseline", "payload_valid"),
        _response("baseline", 200),
        [(_request("attack", "payload_attack"), _response("attack", 200, "yslfuzz_probe"), _payload())],
        scan_run_id="scan_1",
    )

    assert detector_results
    assert findings


def test_finding_builder_aggregates_detector_results_into_security_findings() -> None:
    result = DetectorResult(
        detector_id="detector_1",
        request_id="request_attack",
        response_id="response_attack",
        matched=True,
        confidence=FindingConfidence.LOW,
        severity=FindingSeverity.LOW,
        evidence=[
            Evidence(
                evidence_type="marker_reflection",
                source="test",
                description="marker reflected",
                request_id="request_attack",
                response_id="response_attack",
                observed_value_preview="yslfuzz_probe",
                redacted=False,
            )
        ],
        reason="marker reflected",
        metadata={
            "detector_name": "ReflectionDetector",
            "endpoint_id": "endpoint_1",
            "payload_id": "payload_attack",
            "attack_category": AttackCategory.XSS.value,
            "target_field": "name",
            "target_location": "BODY",
        },
    )

    findings = FindingBuilder().build([result], scan_run_id="scan_1")

    assert len(findings) == 1
    assert findings[0].attack_category == AttackCategory.XSS
    assert findings[0].request_ids == ["request_attack"]


def _request(prefix: str, payload_id: str) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        payload_id=payload_id,
        method=HttpMethod.GET,
        url="https://api.example.test/users",
    )


def _response(prefix: str, status_code: int, body_preview: str | None = None) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_preview=body_preview,
        body_hash=body_preview or "hash",
        body_size_bytes=len(body_preview or "body"),
    )


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.XSS,
        content_type="application/json",
        generation_strategy="attack",
        seed=1,
        parent_payload_id="payload_valid",
        metadata={"non_executing": True, "target_field": "name", "target_location": "BODY"},
    )
