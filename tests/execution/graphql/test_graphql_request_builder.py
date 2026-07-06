from yslfuzz.execution.graphql import GraphQLExecutionConfig, GraphQLRequestBuilder
from yslfuzz.models.base import REDACTED_VALUE
from yslfuzz.models.enums import HttpMethod, PayloadKind
from yslfuzz.models.payload import PayloadCandidate


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id="endpoint_graphql_user",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body={
            "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }",
            "variables": {"id": "yslfuzz-id-001"},
            "operationName": "YSLFuzzUser",
        },
        headers={"X-Trace": "trace-1"},
        generation_strategy="test",
        seed=0,
        metadata={
            "graphql_operation_name": "YSLFuzzUser",
            "graphql_operation_type": "query",
        },
    )


def test_graphql_request_builder_builds_post_request_to_default_endpoint() -> None:
    request = GraphQLRequestBuilder().build(
        "http://localhost:8080",
        _payload(),
        scan_run_id="scan_1",
    )

    assert request.method == HttpMethod.POST
    assert request.url == "http://localhost:8080/graphql"
    assert request.endpoint_id == "endpoint_graphql_user"
    assert request.payload_id is not None


def test_graphql_request_builder_supports_custom_endpoint_path() -> None:
    request = GraphQLRequestBuilder(
        GraphQLExecutionConfig(graphql_endpoint_path="/api/graphql"),
    ).build("http://localhost:8080/root", _payload())

    assert request.url == "http://localhost:8080/api/graphql"


def test_graphql_request_builder_sets_json_headers_and_preserves_safe_headers() -> None:
    request = GraphQLRequestBuilder().build("http://localhost:8080", _payload())

    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Accept"] == "application/json"
    assert request.headers["X-Trace"] == "trace-1"


def test_graphql_request_builder_includes_body_fields() -> None:
    request = GraphQLRequestBuilder().build("http://localhost:8080", _payload())

    assert isinstance(request.body, dict)
    assert request.body["query"].startswith("query YSLFuzzUser")
    assert request.body["variables"] == {"id": "yslfuzz-id-001"}
    assert request.body["operationName"] == "YSLFuzzUser"


def test_graphql_request_builder_does_not_leak_auth_material_in_repr() -> None:
    payload = _payload()
    payload.headers["Authorization"] = "Bearer raw-secret"

    request = GraphQLRequestBuilder().build("http://localhost:8080", payload)

    assert request.headers["Authorization"] == REDACTED_VALUE
    assert "raw-secret" not in repr(request)
