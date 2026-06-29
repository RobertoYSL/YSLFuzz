from typing import Any

import httpx
import pytest

from yslfuzz.execution import (
    DestructiveMethodBlockedError,
    HttpExecutor,
    RequestBuilder,
    ScopeValidator,
    ScopeViolationError,
)
from yslfuzz.models import (
    ApiStyle,
    ExecutionStatus,
    FieldType,
    GeneratedParameter,
    HttpMethod,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    REDACTED_VALUE,
    ScopeDefinition,
    SessionState,
    Target,
)
from yslfuzz.models.schema import Endpoint


def test_builds_get_request_with_query_parameters() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    payload = _payload(
        endpoint.endpoint_id,
        parameters=[
            GeneratedParameter(
                name="limit",
                location=ParameterLocation.QUERY,
                value=25,
                field_type=FieldType.INTEGER,
            )
        ],
    )

    request = RequestBuilder().build(endpoint, payload, _target(), scan_run_id="scan_1")

    assert request.method == HttpMethod.GET
    assert request.url == "https://api.example.test/users"
    assert request.query_params == {"limit": 25}


def test_builds_get_request_with_path_parameters() -> None:
    endpoint = _endpoint(path="/users/{user_id}", method=HttpMethod.GET)
    payload = _payload(
        endpoint.endpoint_id,
        parameters=[
            GeneratedParameter(
                name="user_id",
                location=ParameterLocation.PATH,
                value="user 123",
                field_type=FieldType.STRING,
            )
        ],
    )

    request = RequestBuilder().build(endpoint, payload, _target(), scan_run_id="scan_1")

    assert request.url == "https://api.example.test/users/user%20123"
    assert request.path_params == {"user_id": "user 123"}


def test_builds_post_request_with_json_body() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.POST)
    payload = _payload(endpoint.endpoint_id, body={"email": "user@example.test", "name": "alice"})

    request = RequestBuilder().build(endpoint, payload, _target(), scan_run_id="scan_1")

    assert request.method == HttpMethod.POST
    assert request.body == {"email": "user@example.test", "name": "alice"}
    assert request.headers["Content-Type"] == "application/json"


def test_headers_and_cookies_are_merged_from_session_and_payload() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    payload = _payload(
        endpoint.endpoint_id,
        headers={"X-Payload": "payload"},
        cookies={"payload_cookie": "payload-cookie"},
        parameters=[
            GeneratedParameter(
                name="X-Trace",
                location=ParameterLocation.HEADER,
                value="trace-1",
                field_type=FieldType.STRING,
            )
        ],
    )
    session = SessionState(
        headers={"X-Session": "session"},
        cookies={"session_cookie": "session-cookie"},
    )

    request = RequestBuilder().build(endpoint, payload, _target(), session, scan_run_id="scan_1")

    assert request.headers["X-Session"] == "session"
    assert request.headers["X-Payload"] == "payload"
    assert request.headers["X-Trace"] == "trace-1"
    assert request.cookies == {
        "session_cookie": REDACTED_VALUE,
        "payload_cookie": REDACTED_VALUE,
    }


def test_authorization_header_is_redacted_before_request_record_is_persisted() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    payload = _payload(endpoint.endpoint_id)
    session = SessionState(headers={"Authorization": "Bearer raw-token"})

    request = RequestBuilder().build(endpoint, payload, _target(), session, scan_run_id="scan_1")

    assert request.headers["Authorization"] == REDACTED_VALUE
    assert "raw-token" not in request.model_dump_json()


def test_cookie_values_are_redacted_before_request_record_is_persisted() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    payload = _payload(endpoint.endpoint_id)
    session = SessionState(cookies={"session_token": "raw-cookie-token"})

    request = RequestBuilder().build(endpoint, payload, _target(), session, scan_run_id="scan_1")

    assert request.cookies["session_token"] == REDACTED_VALUE
    assert "raw-cookie-token" not in request.model_dump_json()


def test_response_record_and_execution_result_are_created_for_successful_response() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())
    executor = HttpExecutor(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"Set-Cookie": "session=secret", "Content-Type": "application/json"},
                    json={"ok": True},
                )
            )
        )
    )

    result = executor.execute(request, scan_run_id="scan_1")

    assert result.status == ExecutionStatus.COMPLETED
    assert result.response_id is not None
    response = executor.response_records[result.response_id]
    assert response.status_code == 200
    assert response.body_hash is not None
    assert response.body_size_bytes > 0
    assert response.headers["set-cookie"] == REDACTED_VALUE


def test_timeout_handling_returns_failed_execution_result() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    result = HttpExecutor(
        client=httpx.Client(transport=httpx.MockTransport(timeout))
    ).execute(request, scan_run_id="scan_1", timeout_seconds=0.01)

    assert result.status == ExecutionStatus.FAILED
    assert result.error_type == "timeout"
    assert result.response_id is None


def test_connection_error_handling_returns_failed_execution_result() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())

    def connection_error(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed")

    result = HttpExecutor(
        client=httpx.Client(transport=httpx.MockTransport(connection_error))
    ).execute(request, scan_run_id="scan_1")

    assert result.status == ExecutionStatus.FAILED
    assert result.error_type == "connection_error"


def test_scope_blocks_disallowed_host_before_execution() -> None:
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())
    calls: list[httpx.Request] = []

    with pytest.raises(ScopeViolationError, match="outside the allowed scope"):
        ScopeValidator().validate(request, ScopeDefinition(allowed_hosts=["other.example.test"]))

    assert calls == []


def test_scope_blocks_blocked_path_before_execution() -> None:
    endpoint = _endpoint(path="/admin/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())
    calls: list[httpx.Request] = []

    with pytest.raises(ScopeViolationError, match="blocked by scope"):
        ScopeValidator().validate(
            request,
            ScopeDefinition(allowed_hosts=["api.example.test"], blocked_paths=["/admin"]),
        )

    assert calls == []


def test_delete_is_blocked_when_destructive_methods_are_disabled() -> None:
    endpoint = _endpoint(path="/users/1", method=HttpMethod.DELETE)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())

    with pytest.raises(DestructiveMethodBlockedError):
        ScopeValidator().validate(request, ScopeDefinition(allowed_hosts=["api.example.test"]))


def test_delete_is_allowed_when_destructive_methods_are_enabled() -> None:
    endpoint = _endpoint(path="/users/1", method=HttpMethod.DELETE)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())

    ScopeValidator().validate(
        request,
        ScopeDefinition(
            allowed_hosts=["api.example.test"],
            allow_destructive_methods=True,
            allowed_methods=[HttpMethod.DELETE],
        ),
    )


@pytest.mark.parametrize("method", [HttpMethod.PUT, HttpMethod.PATCH])
def test_put_and_patch_are_blocked_when_destructive_methods_are_disabled(
    method: HttpMethod,
) -> None:
    endpoint = _endpoint(path="/users/1", method=method)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())

    with pytest.raises(DestructiveMethodBlockedError):
        ScopeValidator().validate(request, ScopeDefinition(allowed_hosts=["api.example.test"]))


def test_execution_tests_do_not_use_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)
    endpoint = _endpoint(path="/users", method=HttpMethod.GET)
    request = RequestBuilder().build(endpoint, _payload(endpoint.endpoint_id), _target())
    executor = HttpExecutor(
        client=httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(204)))
    )

    result = executor.execute(request, scan_run_id="scan_1")

    assert result.status == ExecutionStatus.COMPLETED


def _endpoint(path: str, method: HttpMethod) -> Endpoint:
    return Endpoint(
        api_schema_id="api_schema_1",
        name=f"{method.value.lower()}_{path.strip('/').replace('/', '_') or 'root'}",
        api_style=ApiStyle.REST,
        path=path,
        method=method,
    )


def _payload(
    endpoint_id: str,
    *,
    body: dict[str, Any] | None = None,
    parameters: list[GeneratedParameter] | None = None,
    headers: dict[str, Any] | None = None,
    cookies: dict[str, Any] | None = None,
) -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id=endpoint_id,
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body=body,
        parameters=parameters or [],
        headers=headers or {},
        cookies=cookies or {},
        generation_strategy="unit-test",
        seed=1,
    )


def _target() -> Target:
    return Target(
        name="Example API",
        base_url="https://api.example.test",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTPS,
        scope=ScopeDefinition(allowed_hosts=["api.example.test"]),
    )
