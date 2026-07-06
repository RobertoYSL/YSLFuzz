import httpx

from yslfuzz.execution import HttpExecutor
from yslfuzz.execution.graphql import GraphQLExecutionConfig, GraphQLExecutor
from yslfuzz.models.enums import ApiStyle, PayloadKind, Protocol
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import ScopeDefinition, Target


def _payload(operation_name: str = "YSLFuzzUser") -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id=f"endpoint_{operation_name}",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body={
            "query": f"query {operation_name} {{ health }}",
            "variables": {},
            "operationName": operation_name,
        },
        generation_strategy="test",
        seed=0,
        metadata={
            "graphql_operation_name": operation_name,
            "graphql_operation_type": "query",
        },
    )


def _target() -> Target:
    return Target(
        name="local",
        base_url="http://localhost:8080",
        api_style=ApiStyle.GRAPHQL,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )


def test_graphql_executor_respects_dry_run() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"data": {"health": "ok"}})

    executor = GraphQLExecutor(
        GraphQLExecutionConfig(dry_run=True),
        http_executor=HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler))),
    )

    bundle = executor.execute([_payload()], target=_target(), scan_run_id="scan_1")

    assert calls == []
    assert bundle.planned_count == 1
    assert bundle.skipped_dry_run_count == 1
    assert bundle.executed_count == 0
    assert bundle.response_records == []


def test_graphql_executor_uses_http_executor_and_records_status_and_preview() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/graphql"
        return httpx.Response(200, json={"data": {"health": "ok"}})

    executor = GraphQLExecutor(
        http_executor=HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler))),
    )

    bundle = executor.execute([_payload()], target=_target(), scan_run_id="scan_1")

    assert bundle.executed_count == 1
    assert len(bundle.execution_results) == 1
    assert len(bundle.response_records) == 1
    assert bundle.response_records[0].status_code == 200
    assert bundle.response_records[0].body_preview is not None


def test_graphql_executor_respects_max_graphql_requests() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(200, json={"data": {"health": "ok"}})

    executor = GraphQLExecutor(
        GraphQLExecutionConfig(max_graphql_requests=1),
        http_executor=HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler))),
    )

    bundle = executor.execute(
        [_payload("YSLFuzzOne"), _payload("YSLFuzzTwo")],
        target=_target(),
        scan_run_id="scan_1",
    )

    assert bundle.planned_count == 1
    assert bundle.executed_count == 1
    assert len(seen) == 1


def test_graphql_executor_records_graphql_errors_as_metadata_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errors": [{"message": "validation failed"}]})

    executor = GraphQLExecutor(
        http_executor=HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler))),
    )

    bundle = executor.execute([_payload()], target=_target(), scan_run_id="scan_1")

    assert bundle.application_error_count == 1
    assert bundle.response_records[0].metadata["graphql_has_errors"] is True
    assert bundle.response_records[0].metadata["graphql_error_count"] == 1
