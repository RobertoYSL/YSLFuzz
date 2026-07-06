from yslfuzz.execution import ExecutionBudget, GraphQLExecutionConfig, GraphQLExecutor
from yslfuzz.models import (
    ApiStyle,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    ScanLimits,
    ScopeDefinition,
    Target,
)


def test_graphql_executor_respects_graphql_request_budget_in_dry_run() -> None:
    budget = ExecutionBudget(ScanLimits(max_requests=10, max_graphql_requests=1))
    bundle = GraphQLExecutor(
        GraphQLExecutionConfig(dry_run=True, max_graphql_requests=None),
        execution_budget=budget,
    ).execute(
        [_payload("one"), _payload("two")],
        target=Target(
            name="local",
            base_url="http://localhost:8080",
            api_style=ApiStyle.GRAPHQL,
            protocol=Protocol.HTTP,
            scope=ScopeDefinition(allowed_hosts=["localhost"]),
        ),
        scan_run_id="scan_1",
    )

    assert bundle.planned_count == 1
    assert budget.summary()["requests_skipped_due_to_budget"] == 1


def test_graphql_executor_dry_run_skips_before_http_execution() -> None:
    budget = ExecutionBudget()
    bundle = GraphQLExecutor(
        GraphQLExecutionConfig(dry_run=True),
        execution_budget=budget,
    ).execute(
        [_payload("one")],
        target=Target(
            name="local",
            base_url="http://localhost:8080",
            api_style=ApiStyle.GRAPHQL,
            protocol=Protocol.HTTP,
            scope=ScopeDefinition(allowed_hosts=["localhost"]),
        ),
        scan_run_id="scan_1",
    )

    assert bundle.executed_count == 0
    assert budget.summary()["requests_skipped_due_to_dry_run"] == 1


def _payload(suffix: str) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id=f"payload_{suffix}",
        endpoint_id=f"endpoint_{suffix}",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body={"query": "query YSLFuzzPing { ping }", "variables": {}, "operationName": "YSLFuzzPing"},
        generation_strategy="graphql_test",
        seed=0,
        metadata={"api_style": "GRAPHQL", "graphql_operation_name": "YSLFuzzPing"},
    )
