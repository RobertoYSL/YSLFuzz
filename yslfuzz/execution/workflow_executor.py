"""Stateful workflow execution runtime."""

from yslfuzz.auth.injector import AuthInjector
from yslfuzz.execution.bindings import BindingResolutionError, BindingResolver
from yslfuzz.execution.errors import ScopeViolationError
from yslfuzz.execution.executor import HttpExecutor
from yslfuzz.execution.request_builder import RequestBuilder
from yslfuzz.execution.scope import ScopeValidator
from yslfuzz.execution.value_extractor import ValueExtractionEngine, ValueExtractionError
from yslfuzz.models.auth import ResolvedAuthMaterial
from yslfuzz.models.dependency import Workflow, WorkflowStep
from yslfuzz.models.enums import ExecutionStatus
from yslfuzz.models.execution import (
    ExecutionResult,
    RequestRecord,
    ResponseRecord,
    ScanRun,
    SessionState,
    WorkflowExecutionResult,
)
from yslfuzz.models.project import ScanConfiguration, Target
from yslfuzz.models.schema import ApiSchema, Endpoint
from yslfuzz.payloads import PayloadGenerator


class WorkflowExecutor:
    """Execute simple stateful workflows with extraction and binding."""

    def __init__(
        self,
        payload_generator: PayloadGenerator | None = None,
        binding_resolver: BindingResolver | None = None,
        value_extractor: ValueExtractionEngine | None = None,
        request_builder: RequestBuilder | None = None,
        scope_validator: ScopeValidator | None = None,
        http_executor: HttpExecutor | None = None,
        auth_injector: AuthInjector | None = None,
    ) -> None:
        self._payload_generator = payload_generator or PayloadGenerator(seed=0)
        self._binding_resolver = binding_resolver or BindingResolver()
        self._value_extractor = value_extractor or ValueExtractionEngine()
        self._request_builder = request_builder or RequestBuilder()
        self._scope_validator = scope_validator or ScopeValidator()
        self._http_executor = http_executor or HttpExecutor()
        self._auth_injector = auth_injector or AuthInjector()

    def execute(
        self,
        workflow: Workflow,
        api_schema: ApiSchema,
        target: Target,
        scan_config: ScanConfiguration,
        session_state: SessionState | None = None,
        scan_run: ScanRun | None = None,
        auth_material: ResolvedAuthMaterial | None = None,
    ) -> WorkflowExecutionResult:
        """Execute a workflow and return aggregated execution records."""
        endpoints_by_id = {endpoint.endpoint_id: endpoint for endpoint in api_schema.endpoints}
        known_values: dict[str, object] = {}
        request_records: list[RequestRecord] = []
        response_records: list[ResponseRecord] = []
        execution_results: list[ExecutionResult] = []
        errors: list[str] = []
        status = ExecutionStatus.COMPLETED
        scan_run_id = scan_run.scan_run_id if scan_run is not None else "scan_workflow"

        for step in sorted(workflow.steps, key=lambda item: item.order):
            endpoint = endpoints_by_id.get(step.endpoint_id)
            if endpoint is None:
                errors.append(f"Workflow step references unknown endpoint_id '{step.endpoint_id}'")
                status = ExecutionStatus.FAILED
                if not step.optional:
                    break
                continue

            try:
                request_record = self._execute_step(
                    step,
                    endpoint,
                    target,
                    scan_config,
                    session_state,
                    scan_run_id,
                    known_values,
                    request_records,
                    response_records,
                    execution_results,
                    auth_material,
                )
            except (BindingResolutionError, ScopeViolationError, ValueExtractionError) as exc:
                errors.append(str(exc))
                status = ExecutionStatus.FAILED
                if not step.optional:
                    break
                continue

            if request_record is None:
                status = ExecutionStatus.FAILED
                if not step.optional:
                    break

        return WorkflowExecutionResult(
            workflow_id=workflow.workflow_id,
            status=status,
            request_records=request_records,
            response_records=response_records,
            execution_results=execution_results,
            known_values=dict(known_values),
            errors=errors,
        )

    def _execute_step(
        self,
        step: WorkflowStep,
        endpoint: Endpoint,
        target: Target,
        scan_config: ScanConfiguration,
        session_state: SessionState | None,
        scan_run_id: str,
        known_values: dict[str, object],
        request_records: list[RequestRecord],
        response_records: list[ResponseRecord],
        execution_results: list[ExecutionResult],
        auth_material: ResolvedAuthMaterial | None,
    ) -> RequestRecord | None:
        payload = self._payload_generator.generate_for_endpoint(endpoint)
        payload = self._binding_resolver.apply(
            payload,
            step.input_bindings,
            known_values,
            required=not step.optional,
        )
        request_record = self._request_builder.build(
            endpoint,
            payload,
            target,
            session_state=session_state,
            scan_run_id=scan_run_id,
        )
        request_record = self._auth_injector.apply(request_record, auth_material)
        request_record.workflow_step_id = step.workflow_step_id
        request_records.append(request_record)
        self._scope_validator.validate(request_record, target.scope)

        execution_result = self._http_executor.execute(
            request_record,
            scan_run_id=scan_run_id,
            timeout_seconds=scan_config.request_timeout_seconds,
            auth_material=auth_material,
        )
        execution_results.append(execution_result)
        if execution_result.status != ExecutionStatus.COMPLETED or execution_result.response_id is None:
            return None

        response_record = self._http_executor.response_records.get(execution_result.response_id)
        if response_record is None:
            return None
        response_records.append(response_record)
        self._extract_step_values(step, response_record, known_values)
        return request_record

    def _extract_step_values(
        self,
        step: WorkflowStep,
        response_record: ResponseRecord,
        known_values: dict[str, object],
    ) -> None:
        for extractor in step.output_extractors:
            extracted_values = self._value_extractor.extract(
                response_record,
                extractor,
                required=not step.optional,
            )
            known_values.update(extracted_values)
