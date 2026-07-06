"""GraphQL execution orchestration using the shared HTTP executor."""

from collections.abc import Sequence
from dataclasses import dataclass, field
import json

from yslfuzz.auth import AuthInjector
from yslfuzz.execution.executor import HttpExecutor
from yslfuzz.execution.graphql.config import GraphQLExecutionConfig
from yslfuzz.execution.graphql.request_builder import GraphQLRequestBuilder
from yslfuzz.execution.limits import ExecutionBudget
from yslfuzz.execution.scope import ScopeValidator
from yslfuzz.models.auth import ResolvedAuthMaterial
from yslfuzz.models.enums import ApiStyle, ExecutionStatus
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import Target


@dataclass
class GraphQLExecutionBundle:
    """GraphQL execution records and safe summary counters."""

    request_records: list[RequestRecord] = field(default_factory=list)
    response_records: list[ResponseRecord] = field(default_factory=list)
    execution_results: list[ExecutionResult] = field(default_factory=list)
    planned_count: int = 0
    executed_count: int = 0
    skipped_dry_run_count: int = 0
    transport_error_count: int = 0
    application_error_count: int = 0


class GraphQLExecutor:
    """Execute valid GraphQL payloads through existing HTTP infrastructure."""

    def __init__(
        self,
        config: GraphQLExecutionConfig | None = None,
        http_executor: HttpExecutor | None = None,
        auth_injector: AuthInjector | None = None,
        scope_validator: ScopeValidator | None = None,
        request_builder: GraphQLRequestBuilder | None = None,
        execution_budget: ExecutionBudget | None = None,
    ) -> None:
        self.config = config or GraphQLExecutionConfig()
        self.http_executor = http_executor or HttpExecutor()
        self.auth_injector = auth_injector or AuthInjector()
        self.scope_validator = scope_validator or ScopeValidator()
        self.request_builder = request_builder or GraphQLRequestBuilder(self.config)
        self.execution_budget = execution_budget

    def execute(
        self,
        payloads: Sequence[PayloadCandidate],
        *,
        target: Target,
        scan_run_id: str,
        auth_material: ResolvedAuthMaterial | None = None,
    ) -> GraphQLExecutionBundle:
        """Build and optionally execute GraphQL requests."""
        bundle = GraphQLExecutionBundle()
        for payload in self._limited_payloads(payloads):
            if self.execution_budget is not None:
                decision = self.execution_budget.allow_request(
                    payload.endpoint_id,
                    payload.payload_kind,
                    ApiStyle.GRAPHQL,
                )
                if not decision.allowed:
                    if decision.reason == "timeout":
                        bundle.transport_error_count += 0
                    continue
            request = self.request_builder.build(
                target.base_url,
                payload,
                scan_run_id=scan_run_id,
            )
            request = self.auth_injector.apply(request, auth_material)
            self.scope_validator.validate(request, target.scope)
            bundle.request_records.append(request)
            bundle.planned_count += 1
            if self.execution_budget is not None:
                self.execution_budget.record_planned(payload.endpoint_id, ApiStyle.GRAPHQL)

            if self.config.dry_run or not self.config.execute_graphql:
                bundle.skipped_dry_run_count += 1
                if self.execution_budget is not None:
                    self.execution_budget.mark_dry_run_skip()
                continue

            result = self.http_executor.execute(
                request,
                scan_run_id=scan_run_id,
                timeout_seconds=self.config.timeout or 10.0,
                auth_material=auth_material,
            )
            bundle.execution_results.append(result)
            if self.execution_budget is not None:
                if result.status == ExecutionStatus.COMPLETED:
                    self.execution_budget.record_executed()
                self.execution_budget.record_retries(result.retry_count)
            if result.status == ExecutionStatus.FAILED:
                bundle.transport_error_count += 1
                continue
            bundle.executed_count += 1
            response = self._response_for_result(result)
            if response is None:
                continue
            self._annotate_graphql_response(response)
            if response.metadata.get("graphql_has_errors") is True:
                bundle.application_error_count += int(response.metadata.get("graphql_error_count", 0))
            bundle.response_records.append(response)
        return bundle

    def _limited_payloads(
        self,
        payloads: Sequence[PayloadCandidate],
    ) -> list[PayloadCandidate]:
        if self.config.max_graphql_requests is None:
            return list(payloads)
        return list(payloads[: self.config.max_graphql_requests])

    def _response_for_result(self, result: ExecutionResult) -> ResponseRecord | None:
        if result.response_id is None:
            return None
        return self.http_executor.response_records.get(result.response_id)

    def _annotate_graphql_response(self, response: ResponseRecord) -> None:
        response.metadata["graphql_has_errors"] = False
        response.metadata["graphql_error_count"] = 0
        if not response.body_preview:
            return
        try:
            data = json.loads(response.body_preview)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        errors = data.get("errors")
        if isinstance(errors, list):
            response.metadata["graphql_has_errors"] = len(errors) > 0
            response.metadata["graphql_error_count"] = len(errors)


__all__ = ["GraphQLExecutionBundle", "GraphQLExecutor"]
