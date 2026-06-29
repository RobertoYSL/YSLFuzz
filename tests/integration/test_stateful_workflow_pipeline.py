from pathlib import Path

import httpx

from yslfuzz.dependency import DependencyAnalyzer, WorkflowBuilder
from yslfuzz.discovery import OpenAPIParser
from yslfuzz.execution import HttpExecutor, WorkflowExecutor
from yslfuzz.models import ApiStyle, ExecutionStatus, Protocol, ScanConfiguration, ScopeDefinition, Target


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


def test_stateful_openapi_workflow_pipeline_executes_post_then_get() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    graph = DependencyAnalyzer().analyze(api_schema)
    workflows = WorkflowBuilder().build_workflows(api_schema, graph)
    workflow = next(item for item in workflows if item.name == "createUser -> getUser")
    target = Target(
        name="Simple Users API",
        base_url=api_schema.base_url,
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )
    executor = WorkflowExecutor(
        http_executor=HttpExecutor(client=httpx.Client(transport=httpx.MockTransport(_stateful_api)))
    )

    result = executor.execute(
        workflow,
        api_schema,
        target,
        ScanConfiguration(target_id=target.target_id, request_timeout_seconds=1.0),
    )

    assert result.status == ExecutionStatus.COMPLETED
    assert result.known_values["user_id"] == "user_123"
    assert [record.method.value for record in result.request_records] == ["POST", "GET"]
    assert result.request_records[1].url == "http://localhost:8000/users/user_123"
    assert [response.status_code for response in result.response_records] == [201, 200]


def test_stateful_workflow_pipeline_does_not_make_external_network_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    test_stateful_openapi_workflow_pipeline_executes_post_then_get()


def _stateful_api(request: httpx.Request) -> httpx.Response:
    if request.method == "POST" and request.url.path == "/users":
        return httpx.Response(201, json={"id": "user_123", "email": "user@example.test"})
    if request.method == "GET" and request.url.path == "/users/user_123":
        return httpx.Response(200, json={"id": "user_123", "email": "user@example.test"})
    return httpx.Response(404, json={"error": "not found"})
