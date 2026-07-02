import httpx
from pydantic import SecretStr

from yslfuzz.auth import AuthInjector
from yslfuzz.execution import HttpExecutor, RequestBuilder
from yslfuzz.models import (
    ApiStyle,
    AuthType,
    ExecutionStatus,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    REDACTED_VALUE,
    ResolvedAuthMaterial,
    ScopeDefinition,
    Target,
)
from yslfuzz.models.schema import Endpoint


def test_request_execution_pipeline_applies_auth_before_mock_execution() -> None:
    captured_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers["Authorization"] = request.headers["Authorization"]
        return httpx.Response(200, json={"ok": True})

    endpoint = Endpoint(
        api_schema_id="schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )
    request = RequestBuilder().build(
        endpoint,
        PayloadCandidate(
            endpoint_id=endpoint.endpoint_id,
            payload_kind=PayloadKind.VALID,
            content_type="application/json",
            generation_strategy="unit-test",
            seed=1,
        ),
        _target(),
        scan_run_id="scan_1",
    )
    resolved = ResolvedAuthMaterial(
        auth_type=AuthType.BEARER,
        headers={"Authorization": SecretStr("Bearer SENTINEL_ALPHA")},
    )
    request = AuthInjector().apply(request, resolved)
    executor = HttpExecutor(client=httpx.Client(transport=httpx.MockTransport(handler)))

    result = executor.execute(request, scan_run_id="scan_1", auth_material=resolved)

    assert result.status == ExecutionStatus.COMPLETED
    assert captured_headers["Authorization"] == "Bearer SENTINEL_ALPHA"
    assert request.headers["Authorization"] == REDACTED_VALUE
    assert "SENTINEL_ALPHA" not in request.model_dump_json()


def _target() -> Target:
    return Target(
        name="Example API",
        base_url="https://api.example.test",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTPS,
        scope=ScopeDefinition(allowed_hosts=["api.example.test"]),
    )
