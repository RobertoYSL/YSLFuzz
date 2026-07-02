import json

from yslfuzz.models import (
    ApiStyle,
    HttpMethod,
    RequestRecord,
    ResponseRecord,
    ScanRun,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import JsonReporter
from yslfuzz.reporting.redaction import redact_report_value


def test_reports_include_authentication_enabled_metadata() -> None:
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_auth",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        endpoints=[_endpoint()],
        metadata={
            "authentication_enabled": True,
            "authentication_types": ["bearer"],
            "auth_sources": ["environment"],
            "auth_redaction_applied": True,
        },
    )

    decoded = json.loads(JsonReporter().to_json(report))

    assert decoded["metadata"]["authentication_enabled"] is True
    assert decoded["metadata"]["authentication_types"] == ["bearer"]
    assert decoded["metadata"]["auth_sources"] == ["environment"]
    assert decoded["metadata"]["auth_redaction_applied"] is True


def test_reports_do_not_include_raw_authorization_cookie_or_api_key_values() -> None:
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_auth",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        endpoints=[_endpoint()],
        requests=[
            RequestRecord(
                request_id="request_1",
                scan_run_id="scan_auth",
                endpoint_id="endpoint_1",
                method=HttpMethod.GET,
                url="https://api.example.test/users",
                headers={
                    "Authorization": "Bearer raw-authorization",
                    "Cookie": "session=raw-cookie",
                    "X-API-Key": "raw-api-key",
                    "X-Custom-Auth": "[REDACTED]",
                },
            )
        ],
        responses=[
            ResponseRecord(
                request_id="request_1",
                status_code=200,
                headers={"Set-Cookie": "session=raw-response-cookie"},
                body_preview="token=raw-token-value",
            )
        ],
    )
    encoded = JsonReporter().to_json(report)

    assert "raw-authorization" not in encoded
    assert "raw-cookie" not in encoded
    assert "raw-api-key" not in encoded
    assert "raw-response-cookie" not in encoded
    assert "raw-token-value" not in encoded


def test_redaction_catches_common_auth_header_and_token_names() -> None:
    data = {
        "Authorization": "raw-authorization",
        "Proxy-Authorization": "raw-proxy-authorization",
        "Cookie": "raw-cookie",
        "Set-Cookie": "raw-set-cookie",
        "X-API-Key": "raw-api-key",
        "Api-Key": "raw-api-key-2",
        "API-Key": "raw-api-key-3",
        "X-Auth-Token": "raw-auth-token",
        "X-CSRF-Token": "raw-csrf-token",
        "access_token": "raw-access-token",
        "refresh_token": "raw-refresh-token",
        "id_token": "raw-id-token",
        "token": "raw-token",
        "jwt": "raw-jwt",
        "session": "raw-session",
        "secret": "raw-secret",
        "password": "raw-password",
        "passwd": "raw-passwd",
        "credential": "raw-credential",
    }

    encoded = json.dumps(redact_report_value(data))

    for raw_value in data.values():
        assert raw_value not in encoded


def _endpoint() -> Endpoint:
    return Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )
