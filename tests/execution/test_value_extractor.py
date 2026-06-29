import pytest

from yslfuzz.execution import ValueExtractionEngine, ValueExtractionError
from yslfuzz.models import ResponseRecord, ValueExtractor


def test_value_extractor_extracts_id_from_json_body() -> None:
    response = ResponseRecord(request_id="request_1", status_code=201, body_preview='{"id":"user_123"}')
    extractor = ValueExtractor(source="JSON_BODY", expression="$.id", target_name="id")

    values = ValueExtractionEngine().extract(response, extractor)

    assert values == {"id": "user_123"}


def test_value_extractor_extracts_nested_user_id_from_json_body() -> None:
    response = ResponseRecord(
        request_id="request_1",
        status_code=201,
        body_preview='{"user":{"id":"user_123"}}',
    )
    extractor = ValueExtractor(source="JSON_BODY", expression="$.user.id", target_name="user_id")

    values = ValueExtractionEngine().extract(response, extractor)

    assert values == {"user_id": "user_123", "id": "user_123"}


def test_value_extractor_handles_missing_required_value_with_clear_error() -> None:
    response = ResponseRecord(request_id="request_1", status_code=201, body_preview='{"name":"alice"}')
    extractor = ValueExtractor(source="JSON_BODY", expression="$.id", target_name="id")

    with pytest.raises(ValueExtractionError, match="Could not extract required value"):
        ValueExtractionEngine().extract(response, extractor)


def test_value_extractor_handles_optional_missing_value_safely() -> None:
    response = ResponseRecord(request_id="request_1", status_code=201, body_preview='{"name":"alice"}')
    extractor = ValueExtractor(source="JSON_BODY", expression="$.id", target_name="id")

    assert ValueExtractionEngine().extract(response, extractor, required=False) == {}


def test_value_extractor_extracts_from_headers() -> None:
    response = ResponseRecord(
        request_id="request_1",
        status_code=201,
        headers={"X-Request-ID": "request-token"},
    )
    extractor = ValueExtractor(source="HEADER", expression="x-request-id", target_name="request_id")

    assert ValueExtractionEngine().extract(response, extractor)["request_id"] == "request-token"


def test_value_extractor_extracts_from_cookies() -> None:
    response = ResponseRecord(
        request_id="request_1",
        status_code=201,
        cookies={"session_id": "session-123"},
    )
    extractor = ValueExtractor(source="COOKIE", expression="session_id", target_name="session_id")

    assert ValueExtractionEngine().extract(response, extractor)["session_id"] == "session-123"
