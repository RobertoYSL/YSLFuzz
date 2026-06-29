from datetime import UTC, datetime

from yslfuzz.analysis import FindingFingerprinter
from yslfuzz.models import (
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    ParameterLocation,
    SecurityFinding,
)


def test_same_finding_data_produces_same_fingerprint_across_runs() -> None:
    first = FindingFingerprinter().fingerprint(_finding(request_ids=["request_1"]))
    second = FindingFingerprinter().fingerprint(_finding(request_ids=["request_2"]))

    assert first.fingerprint_hash == second.fingerprint_hash


def test_different_endpoints_produce_different_fingerprints() -> None:
    first = FindingFingerprinter().fingerprint(_finding(endpoint_id="endpoint_1"))
    second = FindingFingerprinter().fingerprint(_finding(endpoint_id="endpoint_2"))

    assert first.fingerprint_hash != second.fingerprint_hash


def test_different_attack_categories_produce_different_fingerprints() -> None:
    first = FindingFingerprinter().fingerprint(_finding(category=AttackCategory.SQL_INJECTION))
    second = FindingFingerprinter().fingerprint(_finding(category=AttackCategory.XSS))

    assert first.fingerprint_hash != second.fingerprint_hash


def test_different_detector_or_evidence_types_produce_different_fingerprints() -> None:
    first = FindingFingerprinter().fingerprint(_finding(evidence_type="status_code"))
    second = FindingFingerprinter().fingerprint(_finding(evidence_type="marker_reflection"))

    assert first.fingerprint_hash != second.fingerprint_hash


def test_fingerprint_excludes_timestamps_request_ids_response_ids_and_raw_secrets() -> None:
    finding = _finding(
        request_ids=["request_raw-secret"],
        response_ids=["response_raw-secret"],
        created_at=datetime(2030, 1, 1, tzinfo=UTC),
        evidence_preview="raw-secret-token",
    )
    fingerprint = FindingFingerprinter().fingerprint(finding)
    encoded = fingerprint.model_dump_json()

    assert "2030" not in encoded
    assert "request_raw-secret" not in encoded
    assert "response_raw-secret" not in encoded
    assert "raw-secret-token" not in encoded


def _finding(
    *,
    endpoint_id: str = "endpoint_1",
    category: AttackCategory = AttackCategory.SQL_INJECTION,
    evidence_type: str = "status_code",
    request_ids: list[str] | None = None,
    response_ids: list[str] | None = None,
    created_at: datetime | None = None,
    evidence_preview: str | None = "200->500",
) -> SecurityFinding:
    return SecurityFinding(
        scan_run_id="scan_1",
        endpoint_id=endpoint_id,
        title="StatusCodeAnomalyDetector signal for name",
        description="5xx status anomaly",
        attack_category=category,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        affected_parameter="name",
        affected_location=ParameterLocation.BODY,
        payload_id="payload_attack",
        request_ids=request_ids or ["request_1"],
        response_ids=response_ids or ["response_1"],
        evidence=[
            Evidence(
                evidence_type=evidence_type,
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id=(request_ids or ["request_1"])[0],
                response_id=(response_ids or ["response_1"])[0],
                observed_value_preview=evidence_preview,
                redacted=False,
            )
        ],
        metadata={"detector_id": "detector_status_code_anomaly"},
        created_at=created_at or datetime(2029, 1, 1, tzinfo=UTC),
    )
