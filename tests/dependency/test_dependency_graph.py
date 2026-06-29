from yslfuzz.dependency import DependencyAnalyzer, WorkflowBuilder
from yslfuzz.models import (
    ApiSchema,
    ApiStyle,
    Endpoint,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    RequestBodyDefinition,
    ResponseDefinition,
)


def test_dependency_graph_creation_from_simple_api_schema() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())

    assert graph.api_schema_id == "api_schema_dependency"
    assert graph.nodes
    assert graph.edges


def test_endpoint_nodes_are_created() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())

    endpoint_nodes = [node for node in graph.nodes if node.node_type == "ENDPOINT"]

    assert {node.label for node in endpoint_nodes} == {
        "POST /users",
        "GET /users/{user_id}",
        "PUT /users/{user_id}",
        "PATCH /users/{user_id}",
        "DELETE /users/{user_id}",
        "GET /admin/users/{user_id}",
    }


def test_field_and_value_nodes_are_created_for_identifier_like_fields() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())

    assert any(node.node_type == "FIELD" and "user_id" in node.label for node in graph.nodes)
    assert any(node.node_type == "VALUE" and node.label == "user_id" for node in graph.nodes)


def test_post_endpoint_returning_id_produces_returns_id_and_produces_edges() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())
    post_node = _endpoint_node(graph, "POST /users")

    assert _has_edge(graph, post_node.node_id, "RETURNS_ID")
    assert _has_edge(graph, post_node.node_id, "PRODUCES")


def test_get_endpoint_with_path_id_consumes_uses_id_and_consumes_edges() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())
    get_node = _endpoint_node(graph, "GET /users/{user_id}")

    assert _has_incoming_edge(graph, get_node.node_id, "USES_ID")
    assert _has_incoming_edge(graph, get_node.node_id, "CONSUMES")


def test_put_and_patch_endpoints_are_classified_as_updates_resource() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())
    put_node = _endpoint_node(graph, "PUT /users/{user_id}")
    patch_node = _endpoint_node(graph, "PATCH /users/{user_id}")

    assert _has_edge(graph, put_node.node_id, "UPDATES_RESOURCE")
    assert _has_edge(graph, patch_node.node_id, "UPDATES_RESOURCE")


def test_delete_endpoint_is_classified_as_deletes_resource() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())
    delete_node = _endpoint_node(graph, "DELETE /users/{user_id}")

    assert _has_edge(graph, delete_node.node_id, "DELETES_RESOURCE")


def test_auth_required_endpoint_receives_requires_auth_relationship() -> None:
    graph = DependencyAnalyzer().analyze(_api_schema())
    auth_node = _endpoint_node(graph, "GET /admin/users/{user_id}")

    assert _has_incoming_edge(graph, auth_node.node_id, "REQUIRES_AUTH")


def test_workflow_builder_creates_simple_post_to_get_workflow() -> None:
    api_schema = _api_schema()
    graph = DependencyAnalyzer().analyze(api_schema)

    workflows = WorkflowBuilder().build_workflows(api_schema, graph)

    assert any(workflow.name == "createUser -> getUser" for workflow in workflows)


def test_workflow_builder_creates_input_bindings_for_consumed_path_id() -> None:
    api_schema = _api_schema()
    graph = DependencyAnalyzer().analyze(api_schema)

    workflow = next(
        workflow
        for workflow in WorkflowBuilder().build_workflows(api_schema, graph)
        if workflow.name == "createUser -> getUser"
    )

    assert workflow.steps[1].input_bindings
    assert workflow.steps[1].input_bindings[0].source == "user_id"
    assert workflow.steps[1].input_bindings[0].target == "path.user_id"


def test_workflow_builder_creates_output_extractors_for_response_id_fields() -> None:
    api_schema = _api_schema()
    graph = DependencyAnalyzer().analyze(api_schema)

    workflow = next(
        workflow
        for workflow in WorkflowBuilder().build_workflows(api_schema, graph)
        if workflow.name == "createUser -> getUser"
    )

    assert workflow.steps[0].output_extractors
    assert workflow.steps[0].output_extractors[0].expression == "$.id"
    assert workflow.steps[0].output_extractors[0].target_name == "user_id"


def test_dependency_graph_output_is_deterministic_for_same_schema() -> None:
    api_schema = _api_schema()
    first = DependencyAnalyzer().analyze(api_schema)
    second = DependencyAnalyzer().analyze(api_schema)

    assert [(node.node_id, node.node_type, node.label) for node in first.nodes] == [
        (node.node_id, node.node_type, node.label) for node in second.nodes
    ]
    assert [
        (edge.edge_id, edge.source_node_id, edge.target_node_id, edge.dependency_type)
        for edge in first.edges
    ] == [
        (edge.edge_id, edge.source_node_id, edge.target_node_id, edge.dependency_type)
        for edge in second.edges
    ]


def test_dependency_engine_does_not_make_network_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    DependencyAnalyzer().analyze(_api_schema())


def _api_schema() -> ApiSchema:
    endpoints = [
        Endpoint(
            endpoint_id="endpoint_create_user",
            api_schema_id="api_schema_dependency",
            name="createUser",
            api_style=ApiStyle.REST,
            path="/users",
            method=HttpMethod.POST,
            responses=[_user_response(201)],
        ),
        Endpoint(
            endpoint_id="endpoint_get_user",
            api_schema_id="api_schema_dependency",
            name="getUser",
            api_style=ApiStyle.REST,
            path="/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[_user_id_parameter()],
            responses=[_user_response(200)],
        ),
        Endpoint(
            endpoint_id="endpoint_put_user",
            api_schema_id="api_schema_dependency",
            name="replaceUser",
            api_style=ApiStyle.REST,
            path="/users/{user_id}",
            method=HttpMethod.PUT,
            parameters=[_user_id_parameter()],
            request_body=_user_request_body(),
            responses=[_user_response(200)],
        ),
        Endpoint(
            endpoint_id="endpoint_patch_user",
            api_schema_id="api_schema_dependency",
            name="updateUser",
            api_style=ApiStyle.REST,
            path="/users/{user_id}",
            method=HttpMethod.PATCH,
            parameters=[_user_id_parameter()],
            request_body=_user_request_body(),
            responses=[_user_response(200)],
        ),
        Endpoint(
            endpoint_id="endpoint_delete_user",
            api_schema_id="api_schema_dependency",
            name="deleteUser",
            api_style=ApiStyle.REST,
            path="/users/{user_id}",
            method=HttpMethod.DELETE,
            parameters=[_user_id_parameter()],
        ),
        Endpoint(
            endpoint_id="endpoint_admin_get_user",
            api_schema_id="api_schema_dependency",
            name="adminGetUser",
            api_style=ApiStyle.REST,
            path="/admin/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[_user_id_parameter()],
            auth_required=True,
            responses=[_user_response(200)],
        ),
    ]
    return ApiSchema(
        api_schema_id="api_schema_dependency",
        target_id="target_dependency",
        api_style=ApiStyle.REST,
        base_url="http://localhost:8000",
        endpoints=endpoints,
    )


def _user_id_parameter() -> Parameter:
    return Parameter(
        parameter_id="parameter_user_id",
        name="user_id",
        location=ParameterLocation.PATH,
        field_type=FieldType.UUID,
        required=True,
    )


def _user_request_body() -> RequestBodyDefinition:
    return RequestBodyDefinition(
        content_type="application/json",
        fields=[
            FieldDefinition(
                field_id="field_request_user_id",
                name="user_id",
                field_type=FieldType.UUID,
            ),
            FieldDefinition(field_id="field_request_name", name="name", field_type=FieldType.STRING),
        ],
    )


def _user_response(status_code: int) -> ResponseDefinition:
    return ResponseDefinition(
        status_code=status_code,
        content_type="application/json",
        fields=[
            FieldDefinition(field_id="field_response_id", name="id", field_type=FieldType.UUID),
            FieldDefinition(field_id="field_response_email", name="email", field_type=FieldType.EMAIL),
        ],
    )


def _endpoint_node(graph, label: str):  # type: ignore[no-untyped-def]
    return next(node for node in graph.nodes if node.node_type == "ENDPOINT" and node.label == label)


def _has_edge(graph, source_node_id: str, dependency_type: str) -> bool:  # type: ignore[no-untyped-def]
    return any(
        edge.source_node_id == source_node_id and edge.dependency_type == dependency_type
        for edge in graph.edges
    )


def _has_incoming_edge(graph, target_node_id: str, dependency_type: str) -> bool:  # type: ignore[no-untyped-def]
    return any(
        edge.target_node_id == target_node_id and edge.dependency_type == dependency_type
        for edge in graph.edges
    )
