from yslfuzz.analysis import (
    DifferentialResponseDetector,
    ErrorMessageDetector,
    ReflectionDetector,
    SensitiveDataExposureDetector,
    StatusCodeAnomalyDetector,
)
from yslfuzz.models import (
    AttackCategory,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_status_code_anomaly_detector_creates_result_on_5xx_anomaly() -> None:
    results = StatusCodeAnomalyDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("attack"),
        _response("attack", 500),
        _attack_payload(),
    )

    assert results
    assert results[0].severity == FindingSeverity.MEDIUM


def test_error_message_detector_creates_result_on_generic_exception_indicator() -> None:
    results = ErrorMessageDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("attack"),
        _response("attack", 500, body_preview="Unhandled Exception occurred"),
        _attack_payload(),
    )

    assert results
    assert results[0].reason == "generic server error indicator"


def test_reflection_detector_detects_inert_yslfuzz_marker_reflection() -> None:
    results = ReflectionDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("attack"),
        _response("attack", 200, body_preview="hello yslfuzz_xss_probe"),
        _attack_payload(category=AttackCategory.XSS),
    )

    assert results
    assert results[0].severity == FindingSeverity.LOW


def test_differential_response_detector_detects_significant_differences() -> None:
    results = DifferentialResponseDetector().detect(
        _request("baseline"),
        _response("baseline", 200, body_hash="a", body_size_bytes=100, response_time_ms=10),
        _request("attack"),
        _response("attack", 404, body_hash="b", body_size_bytes=300, response_time_ms=500),
        _attack_payload(),
    )

    assert results
    assert "differential" in results[0].reason


def test_sensitive_data_exposure_detector_creates_redacted_evidence_only() -> None:
    results = SensitiveDataExposureDetector().detect(
        _request("baseline"),
        _response("baseline", 200),
        _request("attack"),
        _response("attack", 200, body_preview='{"token":"raw-token-value"}'),
        _attack_payload(),
    )

    assert results
    assert results[0].severity == FindingSeverity.HIGH
    assert "raw-token-value" not in results[0].model_dump_json()
    assert results[0].evidence[0].model_dump(mode="json")["observed_value_preview"] == "[REDACTED]"


def _request(prefix: str) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        payload_id=f"payload_{prefix}",
        method=HttpMethod.GET,
        url="https://api.example.test/users",
    )


def _response(
    prefix: str,
    status_code: int,
    *,
    body_preview: str | None = None,
    body_hash: str | None = "hash",
    body_size_bytes: int = 100,
    response_time_ms: float = 10,
) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_preview=body_preview,
        body_hash=body_hash,
        body_size_bytes=body_size_bytes,
        response_time_ms=response_time_ms,
    )


def _attack_payload(category: AttackCategory = AttackCategory.SQL_INJECTION) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=category,
        content_type="application/json",
        generation_strategy="attack",
        seed=1,
        parent_payload_id="payload_valid",
        metadata={
            "non_executing": True,
            "target_field": "name",
            "target_location": "BODY",
        },
    )
