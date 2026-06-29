from yslfuzz.analysis import FindingDeduplicator
from yslfuzz.models import (
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    ParameterLocation,
    SecurityFinding,
)


def test_deduplicator_merges_duplicate_findings() -> None:
    findings = FindingDeduplicator().deduplicate([_finding("request_1"), _finding("request_2")])

    assert len(findings) == 1


def test_deduplicator_preserves_request_and_response_ids_and_evidence() -> None:
    findings = FindingDeduplicator().deduplicate(
        [
            _finding("request_1", response_id="response_1", evidence_type="status_code"),
            _finding("request_2", response_id="response_2", evidence_type="status_code"),
        ]
    )

    assert findings[0].request_ids == ["request_1", "request_2"]
    assert findings[0].response_ids == ["response_1", "response_2"]
    assert len(findings[0].evidence) == 2


def test_deduplicator_keeps_highest_severity_and_confidence() -> None:
    findings = FindingDeduplicator().deduplicate(
        [
            _finding("request_1", severity=FindingSeverity.LOW, confidence=FindingConfidence.LOW),
            _finding("request_2", severity=FindingSeverity.HIGH, confidence=FindingConfidence.HIGH),
        ]
    )

    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].confidence == FindingConfidence.HIGH


def test_deduplicator_output_ordering_is_deterministic() -> None:
    input_findings = [
        _finding("request_2", endpoint_id="endpoint_b", category=AttackCategory.XSS),
        _finding("request_1", endpoint_id="endpoint_a", category=AttackCategory.SQL_INJECTION),
    ]

    first = [finding.metadata["fingerprint_hash"] for finding in FindingDeduplicator().deduplicate(input_findings)]
    second = [
        finding.metadata["fingerprint_hash"]
        for finding in FindingDeduplicator().deduplicate(list(reversed(input_findings)))
    ]

    assert first == second


def _finding(
    request_id: str,
    *,
    response_id: str = "response_1",
    endpoint_id: str = "endpoint_1",
    category: AttackCategory = AttackCategory.SQL_INJECTION,
    evidence_type: str = "status_code",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    confidence: FindingConfidence = FindingConfidence.MEDIUM,
) -> SecurityFinding:
    return SecurityFinding(
        scan_run_id="scan_1",
        endpoint_id=endpoint_id,
        title="StatusCodeAnomalyDetector signal for name",
        description="status changed",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        affected_parameter="name",
        affected_location=ParameterLocation.BODY,
        payload_id="payload_attack",
        request_ids=[request_id],
        response_ids=[response_id],
        evidence=[
            Evidence(
                evidence_type=evidence_type,
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id=request_id,
                response_id=response_id,
                observed_value_preview="200->500",
                redacted=False,
            )
        ],
        metadata={"detector_id": "detector_status_code_anomaly"},
    )
