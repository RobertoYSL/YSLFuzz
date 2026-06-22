import json

from yslfuzz.models import (
    REDACTED_VALUE,
    Evidence,
    ExecutionStatus,
    FieldType,
    GeneratedParameter,
    HttpMethod,
    ParameterLocation,
    RequestRecord,
    ResponseRecord,
    ScanRun,
    SessionState,
)


def test_models_serialize_to_json() -> None:
    scan = ScanRun(
        project_id="project_1",
        target_id="target_1",
        scan_config_id="scan_config_1",
        status=ExecutionStatus.PENDING,
        api_schema_id="api_schema_1",
    )

    encoded = scan.model_dump_json()
    decoded = json.loads(encoded)

    assert decoded["scan_run_id"].startswith("scan_")
    assert decoded["status"] == "PENDING"
    assert decoded["metadata"] == {}


def test_sensitive_generated_parameter_is_redacted() -> None:
    parameter = GeneratedParameter(
        name="password",
        location=ParameterLocation.BODY,
        value="secret-password",
        field_type=FieldType.PASSWORD,
        sensitive=True,
    )

    assert parameter.model_dump(mode="json")["value"] == REDACTED_VALUE


def test_request_and_response_sensitive_headers_are_redacted() -> None:
    request = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        method=HttpMethod.GET,
        url="http://localhost:8000/users",
        headers={"Authorization": "Bearer secret", "Accept": "application/json"},
        cookies={"session_token": "secret-cookie"},
        body={"api_key": "secret-key", "name": "alice"},
    )
    response = ResponseRecord(
        request_id=request.request_id,
        status_code=200,
        headers={"Set-Cookie": "session=secret"},
        cookies={"refresh_token": "secret-token"},
    )

    serialized_request = request.model_dump(mode="json")
    serialized_response = response.model_dump(mode="json")

    assert serialized_request["headers"]["Authorization"] == REDACTED_VALUE
    assert serialized_request["headers"]["Accept"] == "application/json"
    assert serialized_request["cookies"]["session_token"] == REDACTED_VALUE
    assert serialized_request["body"]["api_key"] == REDACTED_VALUE
    assert serialized_request["body"]["name"] == "alice"
    assert serialized_response["headers"]["Set-Cookie"] == REDACTED_VALUE
    assert serialized_response["cookies"]["refresh_token"] == REDACTED_VALUE


def test_session_state_redacts_auth_material() -> None:
    session = SessionState(
        headers={"Authorization": "Bearer secret"},
        cookies={"session": "cookie-value"},
        auth_tokens={"access_token": "token-value"},
    )

    serialized = session.model_dump(mode="json")

    assert serialized["headers"]["Authorization"] == REDACTED_VALUE
    assert serialized["cookies"]["session"] == "cookie-value"
    assert serialized["auth_tokens"]["access_token"] == REDACTED_VALUE


def test_redacted_evidence_hides_observed_preview() -> None:
    evidence = Evidence(
        evidence_type="sensitive_data",
        source="response",
        description="Token observed",
        observed_value_preview="token-value",
        redacted=True,
    )

    assert evidence.model_dump(mode="json")["observed_value_preview"] == REDACTED_VALUE
