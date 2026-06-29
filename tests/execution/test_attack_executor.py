import httpx

from yslfuzz.execution import (
    AttackExecutionPlan,
    AttackExecutor,
    HttpExecutor,
    RequestBuilder,
    ScopeValidator,
)
from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    ExecutionStatus,
    FieldType,
    GeneratedParameter,
    HttpMethod,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    ScopeDefinition,
    Target,
)
from yslfuzz.models.schema import Endpoint


def test_attack_executor_preserves_scope_validation() -> None:
    endpoint = _endpoint()
    bundle = _executor().execute_plan(
        AttackExecutionPlan(endpoint_id=endpoint.endpoint_id, payloads=[_attack_payload()]),
        endpoint,
        _target(allowed_hosts=["other.example.test"]),
        scan_run_id="scan_1",
    )

    assert bundle.execution_results[0].status == ExecutionStatus.BLOCKED
    assert bundle.execution_results[0].error_type == "ScopeViolationError"


def test_attack_executor_preserves_destructive_method_blocking() -> None:
    endpoint = _endpoint(method=HttpMethod.DELETE)
    bundle = _executor().execute_plan(
        AttackExecutionPlan(endpoint_id=endpoint.endpoint_id, payloads=[_attack_payload()]),
        endpoint,
        _target(),
        scan_run_id="scan_1",
    )

    assert bundle.execution_results[0].status == ExecutionStatus.BLOCKED
    assert bundle.execution_results[0].error_type == "DestructiveMethodBlockedError"


def test_attack_executor_does_not_execute_when_dry_run_is_active() -> None:
    endpoint = _endpoint()
    calls: list[httpx.Request] = []
    executor = _executor(lambda request: calls.append(request) or httpx.Response(200, json={"ok": True}))

    bundle = executor.execute_plan(
        AttackExecutionPlan(endpoint_id=endpoint.endpoint_id, payloads=[_attack_payload()]),
        endpoint,
        _target(),
        scan_run_id="scan_1",
        dry_run=True,
    )

    assert calls == []
    assert bundle.execution_results == []


def test_attack_executor_uses_mock_transport_in_tests() -> None:
    endpoint = _endpoint()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    bundle = _executor(handler).execute_plan(
        AttackExecutionPlan(endpoint_id=endpoint.endpoint_id, payloads=[_attack_payload()]),
        endpoint,
        _target(),
        scan_run_id="scan_1",
    )

    assert calls == ["https://api.example.test/users/123"]
    assert bundle.execution_results[0].status == ExecutionStatus.COMPLETED
    assert bundle.response_records[0].status_code == 200


def _executor(handler: object | None = None) -> AttackExecutor:
    transport = httpx.MockTransport(handler or (lambda _request: httpx.Response(200, json={"ok": True})))
    return AttackExecutor(
        RequestBuilder(),
        ScopeValidator(),
        HttpExecutor(httpx.Client(transport=transport)),
    )


def _endpoint(method: HttpMethod = HttpMethod.GET) -> Endpoint:
    return Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="api_schema_1",
        name="getUser",
        api_style=ApiStyle.REST,
        path="/users/{id}",
        method=method,
    )


def _target(allowed_hosts: list[str] | None = None) -> Target:
    return Target(
        name="api.example.test",
        base_url="https://api.example.test",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTPS,
        scope=ScopeDefinition(
            allowed_hosts=allowed_hosts or ["api.example.test"],
            allowed_methods=[HttpMethod.GET, HttpMethod.POST],
        ),
    )


def _attack_payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack_1",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.SQL_INJECTION,
        content_type="application/json",
        parameters=[
            GeneratedParameter(
                name="id",
                location=ParameterLocation.PATH,
                value="123",
                field_type=FieldType.STRING,
            )
        ],
        generation_strategy="attack",
        seed=1,
        parent_payload_id="payload_valid_1",
        metadata={"non_executing": True},
    )
