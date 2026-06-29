from yslfuzz.analysis import FindingBuilder
from yslfuzz.models import (
    AttackCategory,
    DetectorResult,
    Evidence,
    FindingConfidence,
    FindingSeverity,
)


def test_finding_builder_deduplicates_findings_by_default() -> None:
    findings = FindingBuilder().build(
        [
            _result("request_1", "response_1"),
            _result("request_2", "response_2"),
        ],
        scan_run_id="scan_1",
    )

    assert len(findings) == 1
    assert findings[0].request_ids == ["request_1", "request_2"]
    assert findings[0].metadata["fingerprint_hash"]
    assert findings[0].metadata["deduplicated_count"] == 2


def _result(request_id: str, response_id: str) -> DetectorResult:
    return DetectorResult(
        detector_id="detector_status_code_anomaly",
        request_id=request_id,
        response_id=response_id,
        matched=True,
        confidence=FindingConfidence.MEDIUM,
        severity=FindingSeverity.MEDIUM,
        evidence=[
            Evidence(
                evidence_type="status_code",
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id=request_id,
                response_id=response_id,
                observed_value_preview="200->500",
                redacted=False,
            )
        ],
        reason="5xx status anomaly",
        metadata={
            "detector_name": "StatusCodeAnomalyDetector",
            "endpoint_id": "endpoint_1",
            "payload_id": "payload_attack",
            "attack_category": AttackCategory.SQL_INJECTION.value,
            "target_field": "name",
            "target_location": "BODY",
        },
    )
