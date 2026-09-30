"""REST scan command handler with stateful workflows and oracle detection."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from yslfuzz.analysis import AnalysisEngine, FindingBuilder
from yslfuzz.auth import AuthInjector, AuthResolver
from yslfuzz.cli.scan_args import (
    _analysis_config_from_args,
    _attack_categories_from_args,
    _attack_payloads,
    _auth_profile_from_args,
    _auth_report_metadata,
    _auth_user2_profile_from_args,
    _config_report_metadata,
    _confirm_dangerous_execution,
    _effective_scan_args,
    _execute_payloads,
    _execute_request,
    _http_executor_from_args,
    _mutation_config_from_args,
    _mutation_payloads,
    _print_progress,
    _print_summary,
    _scan_limits_from_args,
    _stability_report_metadata,
    _target_from_args,
    _verbose,
)
from yslfuzz.dependency import DependencyAnalyzer, WorkflowBuilder
from yslfuzz.discovery import OpenAPIParser
from yslfuzz.execution import (
    AttackExecutionConfig,
    AttackExecutionPlanner,
    AttackExecutor,
    DestructiveMethodBlockedError,
    ExecutionBudget,
    ProgressTracker,
    RequestBuilder,
    ScopeValidator,
    WorkflowExecutor,
)
from yslfuzz.models import (
    ApiStyle,
    ExecutionResult,
    ExecutionStatus,
    HttpMethod,
    PayloadCandidate,
    RequestRecord,
    ResponseRecord,
    ScanConfiguration,
    ScanRun,
)
from yslfuzz.payloads import PayloadGenerator
from yslfuzz.reporting import JsonReporter, MetricsCalculator


DESTRUCTIVE_METHODS = {HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH}


def run_scan_command(args: argparse.Namespace) -> int:
    """Run the scan command and return a process exit code."""
    args = _effective_scan_args(args)
    openapi_arg = getattr(args, "openapi", None)
    graphql_schema_arg = getattr(args, "graphql_schema", None)
    if bool(openapi_arg) == bool(graphql_schema_arg):
        raise ValueError("configure exactly one of --openapi or --graphql-schema")
    if graphql_schema_arg is not None:
        from yslfuzz.cli.commands.graphql import _run_graphql_discovery_command

        return _run_graphql_discovery_command(args)
    if not isinstance(openapi_arg, str):
        raise ValueError("--openapi must be a local file path")
    openapi_path = Path(openapi_arg)
    if not openapi_path.is_file():
        raise FileNotFoundError(f"OpenAPI file does not exist: {openapi_path}")
    if args.max_requests is not None and args.max_requests < 0:
        raise ValueError("--max-requests must be greater than or equal to 0")
    if getattr(args, "max_requests_per_endpoint", None) is not None and args.max_requests_per_endpoint < 0:
        raise ValueError("--max-requests-per-endpoint must be greater than or equal to 0")
    if (
        getattr(args, "max_scan_duration_seconds", None) is not None
        and args.max_scan_duration_seconds < 0
    ):
        raise ValueError("--max-scan-duration-seconds must be greater than or equal to 0")
    if getattr(args, "min_request_delay_ms", None) is not None and args.min_request_delay_ms < 0:
        raise ValueError("--min-request-delay-ms must be greater than or equal to 0")
    if getattr(args, "rate_limit_rps", None) is not None and args.rate_limit_rps <= 0:
        raise ValueError("--rate-limit-rps must be greater than 0")
    if getattr(args, "max_retries", 0) < 0:
        raise ValueError("--max-retries must be greater than or equal to 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if args.max_attack_requests_per_endpoint < 0:
        raise ValueError("--max-attack-requests-per-endpoint must be greater than or equal to 0")
    if args.max_mutations_per_payload < 0:
        raise ValueError("--max-mutations-per-payload must be greater than or equal to 0")
    if args.max_mutations_per_field < 0:
        raise ValueError("--max-mutations-per-field must be greater than or equal to 0")
    if not _confirm_dangerous_execution(args, target_url=args.base_url):
        return 0
    if args.execute_attacks and not args.i_understand_this_is_authorized:
        raise ValueError("--execute-attacks requires --i-understand-this-is-authorized")
    if args.execute_mutations and not args.i_understand_mutation_execution_is_authorized:
        raise ValueError(
            "--execute-mutations requires --i-understand-mutation-execution-is-authorized"
        )

    api_schema = OpenAPIParser().parse(openapi_path)
    auth_profile = _auth_profile_from_args(args)
    auth_material = AuthResolver().resolve(auth_profile) if auth_profile is not None else None
    user2_profile = _auth_user2_profile_from_args(args)
    auth_user2_material = (
        AuthResolver().resolve(user2_profile) if user2_profile is not None else None
    )

    target = _target_from_args(args.base_url, args.allow_destructive, args.max_requests)
    if getattr(args, "target_name", None):
        target.name = args.target_name
    target.auth_profile = auth_profile
    attack_categories = _attack_categories_from_args(args.attack_category)
    mutation_config = _mutation_config_from_args(args)
    analysis_config = _analysis_config_from_args(args)
    scan = ScanRun(
        project_id="project_cli",
        target_id=target.target_id,
        scan_config_id="scan_config_cli",
        api_schema_id=api_schema.api_schema_id,
    )

    payloads: list[PayloadCandidate] = []
    requests: list[RequestRecord] = []
    responses: list[ResponseRecord] = []
    execution_results: list[ExecutionResult] = []
    findings = []
    request_builder = RequestBuilder()
    auth_injector = AuthInjector()
    scope_validator = ScopeValidator()
    budget = ExecutionBudget(_scan_limits_from_args(args, api_style=ApiStyle.REST))
    progress = ProgressTracker(total_endpoints=len(api_schema.endpoints))
    executor = _http_executor_from_args(args)

    cli_main = sys.modules.get("yslfuzz.cli.main")
    attack_executor_cls = getattr(cli_main, "AttackExecutor", AttackExecutor) if cli_main else AttackExecutor
    attack_executor = attack_executor_cls(request_builder, scope_validator, http_executor=executor)

    analysis_engine = AnalysisEngine(
        config=analysis_config,
        finding_builder=FindingBuilder(deduplicate=not bool(args.no_deduplicate_findings)),
    )
    # Register OpenAPI endpoints for schema conformance oracle
    analysis_engine.register_endpoints(api_schema.endpoints)
    total_detector_results = 0
    total_raw_findings = 0

    # Stateful workflow execution if requested
    stateful_enabled = bool(getattr(args, "stateful", False))
    executable_workflows = []
    executed_workflows_count = 0
    cumulative_known_values: dict[str, Any] = {}

    if stateful_enabled:
        _verbose(args.verbose, "Stateful workflow analysis enabled.")
        analyzer = DependencyAnalyzer()
        graph = analyzer.analyze(api_schema)
        workflow_builder = WorkflowBuilder()
        all_workflows = workflow_builder.build_workflows(api_schema, graph)
        executable_workflows = [
            w for w in all_workflows if not w.destructive or args.allow_destructive
        ]
        _verbose(
            args.verbose,
            f"Deduced {len(all_workflows)} workflows from dependency graph ({len(executable_workflows)} executable).",
        )

        if not args.dry_run:
            workflow_executor = WorkflowExecutor(
                http_executor=executor,
                auth_injector=auth_injector,
            )
            for workflow in executable_workflows:
                if budget.timed_out():
                    budget.mark_timeout_skip()
                    break
                wf_result = workflow_executor.execute(
                    workflow=workflow,
                    api_schema=api_schema,
                    target=target,
                    scan_config=ScanConfiguration(
                        target_id=target.target_id,
                        request_timeout_seconds=args.timeout,
                    ),
                    scan_run=scan,
                    auth_material=auth_material,
                )
                executed_workflows_count += 1
                requests.extend(wf_result.request_records)
                responses.extend(wf_result.response_records)
                execution_results.extend(wf_result.execution_results)
                for req in wf_result.request_records:
                    budget.record_planned(req.endpoint_id, ApiStyle.REST)
                for res in wf_result.execution_results:
                    if res.status == ExecutionStatus.COMPLETED:
                        budget.record_executed()
                    budget.record_retries(res.retry_count)
                cumulative_known_values.update(wf_result.known_values)

                # Check baseline crashes and schema conformance on workflow responses
                for req, resp in zip(wf_result.request_records, wf_result.response_records):
                    wf_res, wf_find = analysis_engine.analyze_baseline(
                        req, resp, scan_run_id=scan.scan_run_id
                    )
                    total_detector_results += len(wf_res)
                    total_raw_findings += len(wf_find)
                    findings.extend(wf_find)

    for endpoint in api_schema.endpoints:
        if budget.timed_out():
            budget.mark_timeout_skip()
            break
        if endpoint.method is None:
            continue
        if endpoint.method in DESTRUCTIVE_METHODS and not args.allow_destructive:
            _verbose(args.verbose, f"Skipping destructive endpoint {endpoint.method.value} {endpoint.path}")
            continue

        payload = PayloadGenerator(seed=0).generate_for_endpoint(endpoint)
        if cumulative_known_values:
            for param in payload.parameters:
                if param.name in cumulative_known_values:
                    param.value = cumulative_known_values[param.name]
                elif param.name.lower() in ("id", "user_id", "vehicleid", "vehicle_id"):
                    for k, v in cumulative_known_values.items():
                        if k.lower() == param.name.lower() or "id" in k.lower():
                            param.value = v
                            break

        payloads.append(payload)
        progress.total_payloads_generated += 1
        decision = budget.allow_request(endpoint.endpoint_id, payload.payload_kind, ApiStyle.REST)
        if not decision.allowed:
            continue
        baseline_request: RequestRecord | None = None
        baseline_response: ResponseRecord | None = None

        request_record = request_builder.build(
            endpoint=endpoint,
            payload=payload,
            target=target,
            scan_run_id=scan.scan_run_id,
        )
        request_record = auth_injector.apply(request_record, auth_material)
        try:
            scope_validator.validate(request_record, target.scope)
        except DestructiveMethodBlockedError:
            _verbose(args.verbose, f"Blocked destructive endpoint {endpoint.method.value} {endpoint.path}")
            continue
        requests.append(request_record)
        budget.record_planned(endpoint.endpoint_id, ApiStyle.REST)
        progress.total_requests_planned += 1
        baseline_request = request_record

        if args.dry_run:
            budget.mark_dry_run_skip()
            mutation_payloads = _mutation_payloads(endpoint, payload, mutation_config)
            payloads.extend(mutation_payloads)
            progress.total_payloads_generated += len(mutation_payloads)
            if args.include_attack_payloads:
                attack_payloads = _attack_payloads(endpoint, payload, attack_categories)
                payloads.extend(attack_payloads)
                progress.total_payloads_generated += len(attack_payloads)
            progress.endpoints_processed += 1
            continue

        result = _execute_request(
            executor,
            request_record,
            scan_run_id=scan.scan_run_id,
            timeout_seconds=args.timeout,
            auth_material=auth_material,
        )
        execution_results.append(result)
        budget.record_executed()
        budget.record_retries(result.retry_count)
        progress.requests_executed += 1
        if result.response_id is not None and result.response_id in executor.response_records:
            baseline_response = executor.response_records[result.response_id]
            responses.append(baseline_response)

        # Baseline crash (500) and schema conformance check
        if baseline_response is not None and baseline_request is not None:
            base_det_res, base_find = analysis_engine.analyze_baseline(
                baseline_request, baseline_response, scan_run_id=scan.scan_run_id
            )
            total_detector_results += len(base_det_res)
            total_raw_findings += len(base_find)
            findings.extend(base_find)

            # BOLA differential check
            if (
                bool(getattr(args, "enable_bola_check", False))
                and auth_user2_material is not None
                and not args.dry_run
            ):
                u2_req_record = auth_injector.apply(baseline_request, auth_user2_material)
                u2_result = _execute_request(
                    executor,
                    u2_req_record,
                    scan_run_id=scan.scan_run_id,
                    timeout_seconds=args.timeout,
                    auth_material=auth_user2_material,
                )
                if (
                    u2_result.response_id is not None
                    and u2_result.response_id in executor.response_records
                ):
                    u2_resp = executor.response_records[u2_result.response_id]
                    records_for_bola = [(u2_req_record, u2_resp, payload)]
                    det_res, bola_find = analysis_engine.analyze(
                        baseline_request,
                        baseline_response,
                        records_for_bola,
                        scan_run_id=scan.scan_run_id,
                    )
                    total_detector_results += len(det_res)
                    total_raw_findings += len(bola_find)
                    findings.extend(bola_find)

        if args.include_attack_payloads:
            generated_attacks = _attack_payloads(endpoint, payload, attack_categories)
            payloads.extend(generated_attacks)
            progress.total_payloads_generated += len(generated_attacks)
            if args.execute_attacks and baseline_response is not None and baseline_request is not None:
                attack_plan = AttackExecutionPlanner(
                    AttackExecutionConfig(
                        enabled=True,
                        enabled_categories=attack_categories,
                        max_attack_requests_per_endpoint=args.max_attack_requests_per_endpoint,
                        require_explicit_authorization=True,
                        allow_sensitive_fields=False,
                        execute_only_safe_probes=True,
                        dry_run=bool(args.dry_run),
                    )
                ).plan(endpoint, [payload], generated_attacks)
                attack_kwargs: dict[str, Any] = {
                    "endpoint": endpoint,
                    "target": target,
                    "scan_run_id": scan.scan_run_id,
                    "timeout_seconds": args.timeout,
                    "dry_run": bool(args.dry_run),
                }
                if auth_material is not None:
                    attack_kwargs["auth_material"] = auth_material
                attack_bundle = attack_executor.execute_plan(attack_plan, **attack_kwargs)
                requests.extend(attack_bundle.request_records)
                responses.extend(attack_bundle.response_records)
                execution_results.extend(attack_bundle.execution_results)
                for attack_request in attack_bundle.request_records:
                    budget.record_planned(attack_request.endpoint_id, ApiStyle.REST)
                for attack_result in attack_bundle.execution_results:
                    if attack_result.status == ExecutionStatus.COMPLETED:
                        budget.record_executed()
                    budget.record_retries(attack_result.retry_count)
                attack_payload_by_id = {attack.payload_id: attack for attack in generated_attacks}
                attack_records = [
                    (attack_request, attack_response, attack_payload_by_id[attack_request.payload_id])
                    for attack_request in attack_bundle.request_records
                    for attack_response in attack_bundle.response_records
                    if attack_response.request_id == attack_request.request_id
                    and attack_request.payload_id in attack_payload_by_id
                ]
                _, new_findings = analysis_engine.analyze(
                    baseline_request,
                    baseline_response,
                    attack_records,
                    scan_run_id=scan.scan_run_id,
                )
                total_detector_results += analysis_engine.last_total_detector_results
                total_raw_findings += analysis_engine.last_total_raw_findings
                findings.extend(new_findings)
            elif generated_attacks:
                budget.mark_unauthorized_attack_skip(len(generated_attacks))

        mutation_payloads = _mutation_payloads(endpoint, payload, mutation_config)
        payloads.extend(mutation_payloads)
        progress.total_payloads_generated += len(mutation_payloads)
        if args.execute_mutations:
            mutation_bundle = _execute_payloads(
                endpoint=endpoint,
                payloads=mutation_payloads,
                target=target,
                scan_run_id=scan.scan_run_id,
                request_builder=request_builder,
                auth_injector=auth_injector,
                scope_validator=scope_validator,
                executor=executor,
                timeout_seconds=args.timeout,
                max_requests=args.max_requests,
                current_request_count=len(requests),
                auth_material=auth_material,
                budget=budget,
                api_style=ApiStyle.REST,
            )
            requests.extend(mutation_bundle[0])
            responses.extend(mutation_bundle[1])
            execution_results.extend(mutation_bundle[2])
            if baseline_response is not None and baseline_request is not None:
                mutation_payload_by_id = {payload.payload_id: payload for payload in mutation_payloads}
                mutation_records = [
                    (mutation_request, mutation_response, mutation_payload_by_id[mutation_request.payload_id])
                    for mutation_request in mutation_bundle[0]
                    for mutation_response in mutation_bundle[1]
                    if mutation_response.request_id == mutation_request.request_id
                    and mutation_request.payload_id in mutation_payload_by_id
                ]
                _, new_findings = analysis_engine.analyze(
                    baseline_request,
                    baseline_response,
                    mutation_records,
                    scan_run_id=scan.scan_run_id,
                )
                total_detector_results += analysis_engine.last_total_detector_results
                total_raw_findings += analysis_engine.last_total_raw_findings
                findings.extend(new_findings)
        elif mutation_payloads:
            budget.mark_unauthorized_mutation_skip(len(mutation_payloads))
        progress.findings_so_far = len(findings)
        progress.requests_skipped = budget.skipped_requests
        progress.endpoints_processed += 1
        _print_progress(args, progress)

    metrics = MetricsCalculator().calculate(
        scan_run_id=scan.scan_run_id,
        endpoints=api_schema.endpoints,
        payloads=payloads,
        requests=requests,
        responses=responses,
        execution_results=execution_results,
        findings=findings,
    )
    report = JsonReporter().build_report(
        scan,
        endpoints=api_schema.endpoints,
        payloads=payloads,
        requests=requests,
        responses=responses,
        execution_results=execution_results,
        findings=findings,
        target=target,
        metrics=metrics,
        metadata={
            "dry_run": bool(args.dry_run),
            "include_attack_payloads": bool(args.include_attack_payloads),
            "execute_attacks": bool(args.execute_attacks and not args.dry_run),
            "attack_execution_enabled": bool(args.execute_attacks and not args.dry_run),
            "enabled_attack_categories": [category.value for category in attack_categories],
            "total_detector_results": total_detector_results,
            "total_raw_findings": total_raw_findings,
            "total_deduplicated_findings": len(findings),
            "deduplicate_findings": not bool(args.no_deduplicate_findings),
            "analysis_config": analysis_config.summary(),
            "analysis_detectors": analysis_engine.detector_metadata(),
            "mutation_execution_enabled": bool(args.execute_mutations and not args.dry_run),
            "mutation_config": mutation_config.model_dump(mode="json"),
            "random_seed": mutation_config.random_seed,
            "max_mutations_per_payload": mutation_config.max_mutations_per_payload,
            "max_mutations_per_field": mutation_config.max_mutations_per_field,
            "progress": progress.snapshot().model_dump(mode="json"),
            **_auth_report_metadata(auth_profile),
            **_stability_report_metadata(args, budget),
            **_config_report_metadata(args),
            **({
                "stateful_workflows": {
                    "enabled": True,
                    "workflows_detected": len(executable_workflows),
                    "workflows_executed": executed_workflows_count,
                    "known_values_extracted": len(cumulative_known_values),
                }
            } if stateful_enabled else {}),
        },
    )
    output_path = JsonReporter().write_json(report, args.output)
    markdown_path: Path | None = None
    if getattr(args, "markdown", None):
        from yslfuzz.reporting.markdown_reporter import MarkdownReporter

        markdown_path = MarkdownReporter().write_markdown(report, args.markdown)

    _print_summary(
        output_path=output_path,
        markdown_path=markdown_path,
        total_endpoints=metrics.total_endpoints,
        payloads_generated=metrics.payloads_generated,
        valid_payloads_generated=metrics.valid_payloads_generated,
        boundary_payloads_generated=metrics.boundary_payloads_generated,
        invalid_payloads_generated=metrics.invalid_payloads_generated,
        mutated_payloads_generated=metrics.mutated_payloads_generated,
        attack_payloads_generated=metrics.attack_payloads_generated,
        total_requests=metrics.total_requests,
        successful_requests=metrics.successful_requests,
        failed_requests=metrics.failed_requests,
        findings_total=metrics.findings_total,
        dry_run=bool(args.dry_run),
        findings=findings,
        endpoints=api_schema.endpoints,
        workflow_stats={
            "workflows_detected": len(executable_workflows),
            "workflows_executed": executed_workflows_count,
            "known_values_extracted": len(cumulative_known_values),
        }
        if stateful_enabled
        else None,
        target_url=args.base_url,
        preset=getattr(args, "preset", None),
    )
    return 0
