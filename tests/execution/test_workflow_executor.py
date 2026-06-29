import httpx

from yslfuzz.execution import HttpExecutor, WorkflowExecutor
from yslfuzz.models import (
    ApiSchema,
    ApiStyle,
    Endpoint,
    ExecutionStatus,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    Protocol,
    RequestBodyDefinition,
    ResponseDefinition,
    ScanConfiguration,
    ScopeDefinition,
    Target,
    ValueExtractor,
    VariableBinding,
    Workflow,
    WorkflowStep,
)


def test_workflow_executor_executes_post_to_get_workflow() -> None:
    result = _execute_workflow(_workflow())

    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.request_records) == 2
    assert len(result.response_records) == 2
    assert len(result.execution_results) == 2


def test_workflow_executor_stores_extracted_id_in_known_values() -> None:
    result = _execute_workflow(_workflow())

    assert result.known_values["user_id"] == "user_123"
    assert result.known_values["id"] == "user_123"


def test_workflow_executor_applies_extracted_id_to_second_request_path() -> None:
    result = _execute_workflow(_workflow())

    assert result.request_records[1].url == "http://localhost:8000/users/user_123"


def test_workflow_executor_records_request_response_and_result_for_each_step() -> None:
    result = _execute_workflow(_workflow())

    assert all(record.request_id.startswith("request_") for record in result.request_records)
    assert all(record.response_id.startswith("response_") for record in result.response_records)
    assert all(item.status == ExecutionStatus.COMPLETED for item in result.execution_results)


def test_workflow_executor_stops_when_required_extractor_fails() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(201, json={"name": "alice"})

    result = _execute_workflow(_workflow(), handler=handler)

    assert result.status == ExecutionStatus.FAILED
    assert len(calls) == 1
    assert len(result.request_records) == 1
    assert "Could not extract required value" in result.errors[0]


def test_workflow_executor_respects_destructive_method_blocking() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(201, json={"id": "user_123"})
        raise AssertionError("destructive request should not execute")

    result = _execute_workflow(_workflow(consumer_method=HttpMethod.DELETE), handler=handler)

    assert result.status == ExecutionStatus.FAILED
    assert calls == ["POST"]
    assert "DELETE is blocked" in result.errors[0]


def test_workflow_executor_respects_scope_validation() -> None:
    result = _execute_workflow(_workflow(), target_host="otherhost")

    assert result.status == ExecutionStatus.FAILED
    assert not result.execution_results
    assert "outside the allowed scope" in result.errors[0]


def test_workflow_executor_does_not_make_external_network_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    assert _execute_workflow(_workflow()).status == ExecutionStatus.COMPLETED


def _execute_workflow(
    workflow: Workflow,
    handler=None,  # type: ignore[no-untyped-def]
    target_host: str = "localhost",
):
    api_schema = _api_schema(consumer_method=workflow.steps[1].metadata.get("method", HttpMethod.GET))
    transport = httpx.MockTransport(handler or _handler)
    executor = WorkflowExecutor(http_executor=HttpExecutor(client=httpx.Client(transport=transport)))
    target = Target(
        name="local",
        base_url="http://localhost:8000",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=[target_host]),
    )
    scan_config = ScanConfiguration(target_id=target.target_id, request_timeout_seconds=1.0)
    return executor.execute(workflow, api_schema, target, scan_config)


def _handler(request: httpx.Request) -> httpx.Response:
    if request.method == "POST" and request.url.path == "/users":
        return httpx.Response(201, json={"id": "user_123"})
    if request.method == "GET" and request.url.path == "/users/user_123":
        return httpx.Response(200, json={"id": "user_123", "email": "user@example.test"})
    if request.method == "DELETE" and request.url.path == "/users/user_123":
        return httpx.Response(204)
    return httpx.Response(404)


def _workflow(consumer_method: HttpMethod = HttpMethod.GET) -> Workflow:
    return Workflow(
        workflow_id="workflow_create_get_user",
        name="createUser -> getUser",
        steps=[
            WorkflowStep(
                workflow_step_id="workflow_step_create_user",
                endpoint_id="endpoint_create_user",
                order=1,
                output_extractors=[
                    ValueExtractor(source="JSON_BODY", expression="$.id", target_name="user_id")
                ],
                expected_status_codes=[201],
            ),
            WorkflowStep(
                workflow_step_id="workflow_step_get_user",
                endpoint_id="endpoint_get_user",
                order=2,
                input_bindings=[VariableBinding(source="user_id", target="path.user_id")],
                expected_status_codes=[200],
                metadata={"method": consumer_method},
            ),
        ],
    )


def _api_schema(consumer_method: HttpMethod = HttpMethod.GET) -> ApiSchema:
    return ApiSchema(
        api_schema_id="api_schema_workflow",
        target_id="target_1",
        api_style=ApiStyle.REST,
        base_url="http://localhost:8000",
        endpoints=[
            Endpoint(
                endpoint_id="endpoint_create_user",
                api_schema_id="api_schema_workflow",
                name="createUser",
                api_style=ApiStyle.REST,
                path="/users",
                method=HttpMethod.POST,
                request_body=RequestBodyDefinition(
                    content_type="application/json",
                    fields=[FieldDefinition(name="email", field_type=FieldType.EMAIL, required=True)],
                ),
                responses=[ResponseDefinition(status_code=201, fields=[_id_field()])],
            ),
            Endpoint(
                endpoint_id="endpoint_get_user",
                api_schema_id="api_schema_workflow",
                name="getUser",
                api_style=ApiStyle.REST,
                path="/users/{user_id}",
                method=consumer_method,
                parameters=[
                    Parameter(
                        name="user_id",
                        location=ParameterLocation.PATH,
                        field_type=FieldType.STRING,
                        required=True,
                    )
                ],
                responses=[ResponseDefinition(status_code=200, fields=[_id_field()])],
            ),
        ],
    )


def _id_field() -> FieldDefinition:
    return FieldDefinition(name="id", field_type=FieldType.STRING, required=True)
