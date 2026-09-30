"""Unit tests for BaselineCrashDetector."""

from yslfuzz.analysis.detectors import BaselineCrashDetector
from yslfuzz.models.enums import AttackCategory, FindingConfidence, FindingSeverity, HttpMethod, PayloadKind
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


def _make_request(status_code: int = 500) -> tuple[RequestRecord, ResponseRecord]:
    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="ep_users",
        method=HttpMethod.GET,
        url="http://localhost:8000/users",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=status_code,
        body_preview="Internal Server Error: Unhandled Exception",
        body_size_bytes=42,
    )
    return req, resp


def test_baseline_crash_detector_flags_500_on_baseline() -> None:
    detector = BaselineCrashDetector()
    req, resp = _make_request(500)

    results = detector.detect_baseline(req, resp)
    assert len(results) == 1
    result = results[0]
    assert result.matched is True
    assert result.severity == FindingSeverity.HIGH
    assert result.confidence == FindingConfidence.HIGH
    assert "500" in result.reason
    assert result.metadata["status_code"] == 500
    assert result.metadata["oracle_type"] == "baseline_crash"


def test_baseline_crash_detector_ignores_200_on_baseline() -> None:
    detector = BaselineCrashDetector()
    req, resp = _make_request(200)

    results = detector.detect_baseline(req, resp)
    assert len(results) == 0


def test_baseline_crash_detector_detects_in_paired_mode_if_baseline_crashed() -> None:
    detector = BaselineCrashDetector()
    base_req, base_resp = _make_request(502)
    attack_req, attack_resp = _make_request(502)
    payload = PayloadCandidate(
        endpoint_id="ep_users",
        content_type="application/json",
        generation_strategy="test",
        seed=0,
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.INPUT_VALIDATION,
        parameters=[],
    )

    results = detector.detect(base_req, base_resp, attack_req, attack_resp, payload)
    assert len(results) == 1
    assert results[0].severity == FindingSeverity.HIGH
