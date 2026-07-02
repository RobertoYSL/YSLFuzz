import httpx
from pydantic import SecretStr

from yslfuzz.execution import HttpExecutor, WorkflowExecutor
from yslfuzz.models import (
    ApiSchema,
    ApiStyle,
    AuthType,
    Endpoint,
    ExecutionStatus,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    Protocol,
    REDACTED_VALUE,
    RequestBodyDefinition,
    ResolvedAuthMaterial,
    ResponseDefinition,
    ScanConfiguration,
    ScopeDefinition,
    Target,
    ValueExtractor,
    VariableBinding,
    Workflow,
    WorkflowStep,
)


def test_workflow_execution_applies_auth_to_each_step() -> None:
    captured_authorization: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_authorization.append(request.headers["Authorization"])
        if request.method == "POST":
            return httpx.Response(201, json={"id": "user_123"})
        return httpx.Response(200, json={"id": "user_123"})

    resolved = ResolvedAuthMaterial(
        auth_type=AuthType.BEARER,
        headers={"Authorization": SecretStr("Bearer SENTINEL_WORKFLOW")},
    )
    executor = WorkflowExecutor(
        http_executor=HttpExecutor(client=httpx.Client(transport=httpx.MockTransport(handler)))
    )

    result = executor.execute(_workflow(), _api_schema(), _target(), _scan_config(), auth_material=resolved)

    assert result.status == ExecutionStatus.COMPLETED
    assert captured_authorization == ["Bearer SENTINEL_WORKFLOW", "Bearer SENTINEL_WORKFLOW"]
    assert all(request.headers["Authorization"] == REDACTED_VALUE for request in result.request_records)
    assert "SENTINEL_WORKFLOW" not in result.model_dump_json()


def _target() -> Target:
    return Target(
        name="local",
        base_url="http://localhost:8000",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )


def _scan_config() -> ScanConfiguration:
    return ScanConfiguration(target_id="target_1", request_timeout_seconds=1.0)


def _workflow() -> Workflow:
    return Workflow(
        workflow_id="workflow_auth",
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
            ),
        ],
    )


def _api_schema() -> ApiSchema:
    return ApiSchema(
        api_schema_id="schema_workflow_auth",
        target_id="target_1",
        api_style=ApiStyle.REST,
        base_url="http://localhost:8000",
        endpoints=[
            Endpoint(
                endpoint_id="endpoint_create_user",
                api_schema_id="schema_workflow_auth",
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
                api_schema_id="schema_workflow_auth",
                name="getUser",
                api_style=ApiStyle.REST,
                path="/users/{user_id}",
                method=HttpMethod.GET,
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
