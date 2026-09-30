"""Unit tests for BolaDetector (Broken Object Level Authorization / IDOR)."""

from yslfuzz.analysis.detectors import BolaDetector
from yslfuzz.models.enums import AttackCategory, FindingConfidence, FindingSeverity, HttpMethod, PayloadKind
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


def test_bola_detector_flags_unauthorized_200_access() -> None:
    detector = BolaDetector()

    base_req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="ep_veh",
        method=HttpMethod.GET,
        url="http://localhost:8888/identity/api/v2/vehicle/veh_1",
    )
    base_resp = ResponseRecord(
        request_id=base_req.request_id,
        status_code=200,
        body_preview='{"vin": "VIN_USER1"}',
    )

    attack_req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="ep_veh",
        method=HttpMethod.GET,
        url="http://localhost:8888/identity/api/v2/vehicle/veh_1",
        metadata={"bola_test": True, "target_resource_id": "veh_1"},
    )
    attack_resp = ResponseRecord(
        request_id=attack_req.request_id,
        status_code=200,  # User 2 succeeds in accessing User 1 vehicle!
        body_preview='{"vin": "VIN_USER1"}',
    )
    payload = PayloadCandidate(
        endpoint_id="ep_veh",
        content_type="application/json",
        generation_strategy="test",
        seed=0,
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.BROKEN_ACCESS_CONTROL,
        parameters=[],
        metadata={"bola_test": True},
    )

    results = detector.detect(base_req, base_resp, attack_req, attack_resp, payload)
    assert len(results) == 1
    res = results[0]
    assert res.matched is True
    assert res.severity == FindingSeverity.HIGH
    assert res.confidence == FindingConfidence.HIGH
    assert "BOLA" in res.reason
    assert res.metadata["attack_category"] == AttackCategory.BROKEN_ACCESS_CONTROL.value


def test_bola_detector_ignores_properly_denied_403() -> None:
    detector = BolaDetector()

    base_req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="ep_veh",
        method=HttpMethod.GET,
        url="http://localhost:8888/identity/api/v2/vehicle/veh_1",
    )
    base_resp = ResponseRecord(
        request_id=base_req.request_id,
        status_code=200,
    )

    attack_req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="ep_veh",
        method=HttpMethod.GET,
        url="http://localhost:8888/identity/api/v2/vehicle/veh_1",
        metadata={"bola_test": True, "target_resource_id": "veh_1"},
    )
    attack_resp = ResponseRecord(
        request_id=attack_req.request_id,
        status_code=403,  # Properly denied!
        body_preview='{"error": "forbidden"}',
    )
    payload = PayloadCandidate(
        endpoint_id="ep_veh",
        content_type="application/json",
        generation_strategy="test",
        seed=0,
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.BROKEN_ACCESS_CONTROL,
        parameters=[],
        metadata={"bola_test": True},
    )

    results = detector.detect(base_req, base_resp, attack_req, attack_resp, payload)
    assert len(results) == 0
