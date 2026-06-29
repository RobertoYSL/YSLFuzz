"""Opt-in attack payload execution using existing execution safety controls."""

from collections.abc import Sequence

from yslfuzz.execution.attack_plan import AttackExecutionPlan
from yslfuzz.execution.executor import HttpExecutor
from yslfuzz.execution.request_builder import RequestBuilder
from yslfuzz.execution.scope import ScopeValidator
from yslfuzz.models.enums import ExecutionStatus
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord, SessionState
from yslfuzz.models.project import Target
from yslfuzz.models.schema import Endpoint


class AttackExecutionBundle:
    """Records produced by executing an approved attack plan."""

    def __init__(
        self,
        request_records: Sequence[RequestRecord] = (),
        response_records: Sequence[ResponseRecord] = (),
        execution_results: Sequence[ExecutionResult] = (),
    ) -> None:
        self.request_records = list(request_records)
        self.response_records = list(response_records)
        self.execution_results = list(execution_results)


class AttackExecutor:
    """Execute only attack payloads approved by an AttackExecutionPlanner."""

    def __init__(
        self,
        request_builder: RequestBuilder | None = None,
        scope_validator: ScopeValidator | None = None,
        http_executor: HttpExecutor | None = None,
    ) -> None:
        self._request_builder = request_builder or RequestBuilder()
        self._scope_validator = scope_validator or ScopeValidator()
        self._http_executor = http_executor or HttpExecutor()

    def execute_plan(
        self,
        plan: AttackExecutionPlan,
        endpoint: Endpoint,
        target: Target,
        scan_run_id: str,
        session_state: SessionState | None = None,
        timeout_seconds: float = 10.0,
        dry_run: bool = False,
    ) -> AttackExecutionBundle:
        """Build, validate, and execute approved attack requests."""
        requests: list[RequestRecord] = []
        responses: list[ResponseRecord] = []
        results: list[ExecutionResult] = []

        if dry_run:
            return AttackExecutionBundle()

        for payload in plan.payloads:
            request = self._request_builder.build(
                endpoint=endpoint,
                payload=payload,
                target=target,
                session_state=session_state,
                scan_run_id=scan_run_id,
            )
            requests.append(request)
            try:
                self._scope_validator.validate(request, target.scope)
            except Exception as exc:
                results.append(
                    ExecutionResult(
                        request_id=request.request_id,
                        status=ExecutionStatus.BLOCKED,
                        error_type=exc.__class__.__name__,
                        error_message=str(exc),
                    )
                )
                continue

            result = self._http_executor.execute(
                request,
                scan_run_id=scan_run_id,
                timeout_seconds=timeout_seconds,
            )
            results.append(result)
            if result.response_id is not None and result.response_id in self._http_executor.response_records:
                responses.append(self._http_executor.response_records[result.response_id])

        return AttackExecutionBundle(
            request_records=requests,
            response_records=responses,
            execution_results=results,
        )
