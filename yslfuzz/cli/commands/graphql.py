"""GraphQL discovery and execution command handler."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from yslfuzz.analysis import AnalysisEngine, FindingBuilder
from yslfuzz.auth import AuthResolver
from yslfuzz.cli.scan_args import (
    _analysis_config_from_args,
    _attack_categories_from_args,
    _auth_profile_from_args,
    _auth_report_metadata,
    _config_report_metadata,
    _confirm_dangerous_execution,
    _effective_graphql_request_limit,
    _http_executor_from_args,
    _print_summary,
    _scan_limits_from_args,
    _stability_report_metadata,
    _target_from_args,
)
from yslfuzz.discovery.graphql import (
    GraphQLSchemaLoader,
    GraphQLToApiSchemaMapper,
)
from yslfuzz.execution import (
    ExecutionBudget,
    GraphQLExecutionConfig,
    GraphQLExecutor,
)
from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
    ScanRun,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.payloads import (
    GraphQLAttackPayloadGenerator,
    GraphQLMutationConfig,
    GraphQLMutationEngine,
    GraphQLPayloadConfig,
    GraphQLPayloadGenerator,
)
from yslfuzz.reporting import JsonReporter, MetricsCalculator



def _graphql_payload_config_from_args(args: argparse.Namespace) -> GraphQLPayloadConfig:
    if args.graphql_queries_only and args.graphql_mutations_only:
        raise ValueError("--graphql-queries-only conflicts with --graphql-mutations-only")
    include_queries = True
    include_mutations = True
    if args.graphql_queries_only:
        include_mutations = False
    if args.graphql_mutations_only:
        include_queries = False
    if args.graphql_include_mutations:
        include_mutations = True
    return GraphQLPayloadConfig(
        include_queries=include_queries,
        include_mutations=include_mutations,
        include_subscriptions=False,
        max_operations=args.graphql_max_operations,
        max_selection_depth=args.graphql_max_selection_depth,
        max_fields_per_selection=args.graphql_max_fields_per_selection,
        deterministic=True,
        random_seed=0,
    )


def _graphql_execution_config_from_args(args: argparse.Namespace) -> GraphQLExecutionConfig:
    return GraphQLExecutionConfig(
        graphql_endpoint_path=args.graphql_endpoint,
        execute_graphql=bool(getattr(args, "graphql_execute_graphql", True)),
        dry_run=bool(args.dry_run),
        timeout=args.timeout,
        max_graphql_requests=_effective_graphql_request_limit(
            getattr(args, "graphql_max_requests", None),
            args.max_requests,
        ),
    )


def _graphql_mutation_config_from_args(
    args: argparse.Namespace,
    attack_categories: Sequence[AttackCategory],
) -> GraphQLMutationConfig:
    enabled_attack_categories = list(attack_categories) if attack_categories else None
    return GraphQLMutationConfig(
        include_boundary_payloads=bool(args.include_boundary_payloads),
        include_invalid_payloads=bool(args.include_invalid_payloads),
        include_mutated_payloads=bool(args.include_mutated_payloads),
        include_attack_payloads=bool(args.include_attack_payloads),
        enabled_attack_categories=enabled_attack_categories,
        max_mutations_per_payload=args.max_mutations_per_payload,
        max_mutations_per_variable=args.max_mutations_per_field,
        max_attack_payloads_per_operation=args.max_attack_requests_per_endpoint,
        include_sensitive_fields=bool(args.mutate_sensitive_fields),
        allow_invalid_enum_values=bool(args.allow_invalid_enum_values),
        allow_type_confusion=not bool(args.disable_type_confusion),
        allow_null_mutations=not bool(args.disable_null_mutations),
        allow_extra_input_fields=bool(getattr(args, "allow_extra_input_fields", True)),
        allow_missing_required_fields=bool(getattr(args, "allow_missing_required_fields", True)),
        allow_introspection_probe=bool(
            getattr(args, "allow_introspection_probe", False)
            or getattr(args, "graphql_include_introspection_probe", False)
        ),
        allow_error_leakage_probe=bool(getattr(args, "allow_error_leakage_probe", True)),
        allow_reflection_probe=bool(getattr(args, "allow_reflection_probe", True)),
        deterministic=True,
        random_seed=0,
    )


def _graphql_payloads_selected_for_execution(
    *,
    valid_payloads: Sequence[PayloadCandidate],
    mutation_payloads: Sequence[PayloadCandidate],
    attack_payloads: Sequence[PayloadCandidate],
    dry_run: bool,
    execute_mutations: bool,
    execute_attacks: bool,
) -> list[PayloadCandidate]:
    if dry_run:
        return [*valid_payloads, *mutation_payloads, *attack_payloads]
    selected = list(valid_payloads)
    if execute_mutations:
        selected.extend(mutation_payloads)
    if execute_attacks:
        selected.extend(attack_payloads)
    return selected


def _analyze_graphql_execution(
    *,
    analysis_engine: AnalysisEngine,
    payloads: Sequence[PayloadCandidate],
    request_records: Sequence[RequestRecord],
    response_records: Sequence[ResponseRecord],
    scan_run_id: str,
    enable_analysis: bool,
) -> tuple[list[Any], list[Any]]:
    if not enable_analysis:
        return [], []
    payload_by_id = {payload.payload_id: payload for payload in payloads}
    response_by_request_id = {response.request_id: response for response in response_records}
    baseline_records: list[tuple[RequestRecord, ResponseRecord]] = []
    test_records: list[tuple[RequestRecord, ResponseRecord, PayloadCandidate]] = []
    for request in request_records:
        if request.payload_id is None:
            continue
        payload = payload_by_id.get(request.payload_id)
        response = response_by_request_id.get(request.request_id)
        if payload is None or response is None:
            continue
        if payload.payload_kind == PayloadKind.VALID:
            baseline_records.append((request, response))
        else:
            test_records.append((request, response, payload))
    if not baseline_records or not test_records:
        return [], []
    return analysis_engine.analyze_records(
        baseline_records,
        test_records,
        scan_run_id=scan_run_id,
    )


def _graphql_payload_generation_summary(
    schema: object,
    payloads: Sequence[PayloadCandidate],
    config: GraphQLPayloadConfig,
) -> dict[str, Any]:
    query_count = sum(
        payload.metadata.get("graphql_operation_type") == "query"
        for payload in payloads
    )
    mutation_count = sum(
        payload.metadata.get("graphql_operation_type") == "mutation"
        for payload in payloads
    )
    subscription_count = sum(
        payload.metadata.get("graphql_operation_type") == "subscription"
        for payload in payloads
    )
    schema_id = getattr(schema, "schema_id", None)
    return {
        "api_style": "graphql",
        "graphql_schema_id": schema_id,
        "graphql_payloads_generated": len(payloads),
        "graphql_query_payloads_generated": query_count,
        "graphql_mutation_payloads_generated": mutation_count,
        "graphql_subscription_payloads_generated": subscription_count,
        "generated_operation_names": [
            str(payload.metadata.get("graphql_operation_name"))
            for payload in payloads
            if payload.metadata.get("graphql_operation_name") is not None
        ],
        "max_selection_depth": config.max_selection_depth,
        "max_fields_per_selection": config.max_fields_per_selection,
        "execution_enabled": False,
        "note": "GraphQL valid payload generation only; mutation and attack payloads are not enabled.",
    }


def _graphql_mutation_attack_generation_summary(
    payloads: Sequence[PayloadCandidate],
    config: GraphQLMutationConfig,
    *,
    dry_run: bool,
    mutation_execution_enabled: bool,
    attack_execution_enabled: bool,
    executed_request_payload_ids: set[str | None],
) -> dict[str, Any]:
    generated_by_kind = _payload_counts_by_kind(payloads)
    executed_by_kind = _payload_counts_by_kind(
        [payload for payload in payloads if payload.payload_id in executed_request_payload_ids]
    )
    non_valid_generated = (
        generated_by_kind.get(PayloadKind.BOUNDARY.value, 0)
        + generated_by_kind.get(PayloadKind.INVALID.value, 0)
        + generated_by_kind.get(PayloadKind.MUTATED.value, 0)
        + generated_by_kind.get(PayloadKind.ATTACK.value, 0)
    )
    non_valid_executed = (
        executed_by_kind.get(PayloadKind.BOUNDARY.value, 0)
        + executed_by_kind.get(PayloadKind.INVALID.value, 0)
        + executed_by_kind.get(PayloadKind.MUTATED.value, 0)
        + executed_by_kind.get(PayloadKind.ATTACK.value, 0)
    )
    operator_counts: dict[str, int] = {}
    inert_markers: set[str] = set()
    attack_categories: set[str] = set()
    safe_marker_counts = {
        "graphql_safe_sql_marker_payloads_generated": 0,
        "graphql_safe_nosql_marker_payloads_generated": 0,
        "graphql_safe_command_marker_payloads_generated": 0,
        "graphql_safe_ssrf_marker_payloads_generated": 0,
    }
    introspection_probe_generated = False
    for payload in payloads:
        operator = payload.metadata.get("graphql_mutation_operator")
        if isinstance(operator, str):
            operator_counts[operator] = operator_counts.get(operator, 0) + 1
            if operator == "attack_introspection_probe":
                introspection_probe_generated = True
        marker = payload.metadata.get("inert_marker")
        if isinstance(marker, str):
            inert_markers.add(marker)
        if payload.attack_category is not None:
            attack_categories.add(payload.attack_category.value)
            if payload.attack_category == AttackCategory.SQL_INJECTION:
                safe_marker_counts["graphql_safe_sql_marker_payloads_generated"] += 1
            elif payload.attack_category == AttackCategory.NOSQL_INJECTION:
                safe_marker_counts["graphql_safe_nosql_marker_payloads_generated"] += 1
            elif payload.attack_category == AttackCategory.COMMAND_INJECTION:
                safe_marker_counts["graphql_safe_command_marker_payloads_generated"] += 1
            elif payload.attack_category == AttackCategory.SSRF:
                safe_marker_counts["graphql_safe_ssrf_marker_payloads_generated"] += 1
    skipped_dry_run = non_valid_generated if dry_run else 0
    skipped_not_authorized = 0 if dry_run else max(0, non_valid_generated - non_valid_executed)
    return {
        "graphql_valid_payloads_generated": generated_by_kind.get(PayloadKind.VALID.value, 0),
        "graphql_boundary_payloads_generated": generated_by_kind.get(PayloadKind.BOUNDARY.value, 0),
        "graphql_invalid_payloads_generated": generated_by_kind.get(PayloadKind.INVALID.value, 0),
        "graphql_mutated_payloads_generated": generated_by_kind.get(PayloadKind.MUTATED.value, 0),
        "graphql_attack_payloads_generated": generated_by_kind.get(PayloadKind.ATTACK.value, 0),
        "graphql_valid_payloads_executed": executed_by_kind.get(PayloadKind.VALID.value, 0),
        "graphql_boundary_payloads_executed": executed_by_kind.get(PayloadKind.BOUNDARY.value, 0),
        "graphql_invalid_payloads_executed": executed_by_kind.get(PayloadKind.INVALID.value, 0),
        "graphql_mutated_payloads_executed": executed_by_kind.get(PayloadKind.MUTATED.value, 0),
        "graphql_attack_payloads_executed": executed_by_kind.get(PayloadKind.ATTACK.value, 0),
        "graphql_payloads_skipped_not_authorized": skipped_not_authorized,
        "graphql_payloads_skipped_dry_run": skipped_dry_run,
        "graphql_attack_categories_generated": sorted(attack_categories),
        "graphql_mutation_operator_counts": {
            key: operator_counts[key] for key in sorted(operator_counts)
        },
        "graphql_inert_markers_used": sorted(inert_markers),
        "graphql_introspection_probe_generated": introspection_probe_generated,
        **safe_marker_counts,
        "mutation_execution_enabled": mutation_execution_enabled,
        "attack_execution_enabled": attack_execution_enabled,
        "dry_run": dry_run,
        "config": config.model_dump(mode="json"),
    }


def _graphql_execution_summary(
    schema: object,
    config: GraphQLExecutionConfig,
    bundle: object,
    payloads: Sequence[PayloadCandidate],
) -> dict[str, Any]:
    schema_id = getattr(schema, "schema_id", None)
    planned = int(getattr(bundle, "planned_count", 0))
    executed = int(getattr(bundle, "executed_count", 0))
    skipped_dry_run = int(getattr(bundle, "skipped_dry_run_count", 0))
    responses = getattr(bundle, "response_records", [])
    payload_by_id = {payload.payload_id: payload for payload in payloads}
    executed_payloads = [
        payload_by_id[request.payload_id]
        for request in getattr(bundle, "request_records", [])
        if request.payload_id in payload_by_id
    ]
    executed_by_kind = _payload_counts_by_kind(executed_payloads)
    return {
        "api_style": "graphql",
        "graphql_schema_id": schema_id,
        "graphql_endpoint_path": config.graphql_endpoint_path,
        "graphql_requests_planned": planned,
        "graphql_requests_executed": executed,
        "graphql_requests_skipped_dry_run": skipped_dry_run,
        "graphql_responses_received": len(responses),
        "graphql_errors_transport": int(getattr(bundle, "transport_error_count", 0)),
        "graphql_errors_application": int(getattr(bundle, "application_error_count", 0)),
        "graphql_payloads_executed_by_kind": executed_by_kind,
        "execution_enabled": bool(config.execute_graphql and not config.dry_run),
        "dry_run": config.dry_run,
    }


def _payload_counts_by_kind(payloads: Sequence[PayloadCandidate]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for payload in payloads:
        kind = payload.payload_kind.value
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _align_graphql_payload_endpoint_ids(
    payloads: Sequence[PayloadCandidate],
    endpoints: Sequence[Endpoint],
) -> None:
    endpoint_by_operation = {
        (
            endpoint.graphql_operation_type,
            endpoint.graphql_operation_name,
        ): endpoint.endpoint_id
        for endpoint in endpoints
        if endpoint.graphql_operation_type is not None and endpoint.graphql_operation_name is not None
    }
    for payload in payloads:
        operation_type = payload.metadata.get("graphql_operation_type")
        operation_name = payload.metadata.get("graphql_operation_field_name")
        if not isinstance(operation_type, str) or not isinstance(operation_name, str):
            continue
        endpoint_id = endpoint_by_operation.get((operation_type, operation_name))
        if endpoint_id is not None:
            payload.endpoint_id = endpoint_id


def _run_graphql_discovery_command(args: argparse.Namespace) -> int:
    graphql_schema_path = Path(args.graphql_schema)
    if not graphql_schema_path.is_file():
        raise FileNotFoundError(f"GraphQL schema file does not exist: {graphql_schema_path}")
    if args.max_requests is not None and args.max_requests < 0:
        raise ValueError("--max-requests must be greater than or equal to 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if args.max_mutations_per_payload < 0:
        raise ValueError("--max-mutations-per-payload must be greater than or equal to 0")
    if args.max_mutations_per_field < 0:
        raise ValueError("--max-mutations-per-field must be greater than or equal to 0")
    if args.max_attack_requests_per_endpoint < 0:
        raise ValueError("--max-attack-requests-per-endpoint must be greater than or equal to 0")
    if not _confirm_dangerous_execution(args, target_url=args.base_url):
        return 0
    if args.execute_mutations and not args.i_understand_mutation_execution_is_authorized:
        raise ValueError(
            "--execute-mutations requires --i-understand-mutation-execution-is-authorized"
        )
    if args.execute_attacks and not args.i_understand_this_is_authorized:
        raise ValueError("--execute-attacks requires --i-understand-this-is-authorized")
    attack_categories = _attack_categories_from_args(args.attack_category)
    graphql_payload_config = _graphql_payload_config_from_args(args)
    graphql_execution_config = _graphql_execution_config_from_args(args)
    graphql_mutation_config = _graphql_mutation_config_from_args(args, attack_categories)

    loader = GraphQLSchemaLoader()
    graphql_schema = loader.load(graphql_schema_path)
    api_schema = GraphQLToApiSchemaMapper().map(graphql_schema, base_url=args.base_url)
    valid_payloads = GraphQLPayloadGenerator(graphql_payload_config).generate(graphql_schema)
    mutation_payloads = GraphQLMutationEngine(graphql_mutation_config).mutate(
        graphql_schema,
        valid_payloads,
    )
    attack_payloads = GraphQLAttackPayloadGenerator(graphql_mutation_config).generate(
        graphql_schema,
        valid_payloads,
    )
    payloads = [*valid_payloads, *mutation_payloads, *attack_payloads]
    _align_graphql_payload_endpoint_ids(payloads, api_schema.endpoints)
    target = _target_from_args(
        args.base_url,
        args.allow_destructive,
        graphql_execution_config.max_graphql_requests,
        api_style=ApiStyle.GRAPHQL,
    )
    if getattr(args, "target_name", None):
        target.name = args.target_name
    auth_profile = _auth_profile_from_args(args)
    auth_material = AuthResolver().resolve(auth_profile) if auth_profile is not None else None
    target.auth_profile = auth_profile
    budget = ExecutionBudget(_scan_limits_from_args(args, api_style=ApiStyle.GRAPHQL))
    scan = ScanRun(
        project_id="project_cli",
        target_id=target.target_id,
        scan_config_id="scan_config_cli",
        api_schema_id=api_schema.api_schema_id,
    )
    execution_bundle = GraphQLExecutor(
        graphql_execution_config,
        http_executor=_http_executor_from_args(args),
        execution_budget=budget,
    ).execute(
        _graphql_payloads_selected_for_execution(
            valid_payloads=valid_payloads,
            mutation_payloads=mutation_payloads,
            attack_payloads=attack_payloads,
            dry_run=bool(args.dry_run),
            execute_mutations=bool(args.execute_mutations),
            execute_attacks=bool(args.execute_attacks),
        ),
        target=target,
        scan_run_id=scan.scan_run_id,
        auth_material=auth_material,
    )
    graphql_execution_summary = _graphql_execution_summary(
        graphql_schema,
        graphql_execution_config,
        execution_bundle,
        payloads,
    )
    analysis_config = _analysis_config_from_args(args)
    analysis_engine = AnalysisEngine(
        config=analysis_config,
        finding_builder=FindingBuilder(deduplicate=not bool(args.no_deduplicate_findings)),
    )
    detector_results, findings = _analyze_graphql_execution(
        analysis_engine=analysis_engine,
        payloads=payloads,
        request_records=execution_bundle.request_records,
        response_records=execution_bundle.response_records,
        scan_run_id=scan.scan_run_id,
        enable_analysis=bool(getattr(args, "graphql_enable_analysis", True)),
    )
    metrics = MetricsCalculator().calculate(
        scan_run_id=scan.scan_run_id,
        endpoints=api_schema.endpoints,
        payloads=payloads,
        requests=execution_bundle.request_records,
        responses=execution_bundle.response_records,
        execution_results=execution_bundle.execution_results,
        findings=findings,
    )
    report = JsonReporter().build_report(
        scan,
        api_schema=api_schema,
        payloads=payloads,
        requests=execution_bundle.request_records,
        responses=execution_bundle.response_records,
        execution_results=execution_bundle.execution_results,
        findings=findings,
        target=target,
        metrics=metrics,
        metadata={
            "dry_run": bool(args.dry_run),
            "api_style": "graphql",
            "graphql_discovery_only": False,
            "graphql_discovery_summary": graphql_schema.discovery_summary(),
            "graphql_payload_generation_implemented": True,
            "graphql_payload_generation": _graphql_payload_generation_summary(
                graphql_schema,
                payloads,
                graphql_payload_config,
            ),
            "graphql_mutation_attack_generation": _graphql_mutation_attack_generation_summary(
                payloads,
                graphql_mutation_config,
                dry_run=bool(args.dry_run),
                mutation_execution_enabled=bool(args.execute_mutations and not args.dry_run),
                attack_execution_enabled=bool(args.execute_attacks and not args.dry_run),
                executed_request_payload_ids={
                    request.payload_id
                    for request in execution_bundle.request_records
                    for result in execution_bundle.execution_results
                    if result.request_id == request.request_id
                },
            ),
            "graphql_execution": graphql_execution_summary,
            "scan_status_message": (
                "GraphQL discovery, valid payload generation, and execution planning succeeded."
            ),
            "include_attack_payloads": bool(args.include_attack_payloads),
            "execute_attacks": bool(args.execute_attacks and not args.dry_run),
            "attack_execution_enabled": bool(args.execute_attacks and not args.dry_run),
            "enabled_attack_categories": [category.value for category in attack_categories],
            "total_detector_results": len(detector_results),
            "total_raw_findings": analysis_engine.last_total_raw_findings,
            "total_deduplicated_findings": len(findings),
            "deduplicate_findings": not bool(args.no_deduplicate_findings),
            "analysis_config": analysis_config.summary(),
            "analysis_detectors": analysis_engine.detector_metadata(),
            "mutation_execution_enabled": bool(args.execute_mutations and not args.dry_run),
            "mutation_config": graphql_mutation_config.model_dump(mode="json"),
            "random_seed": graphql_payload_config.seed,
            "max_mutations_per_payload": args.max_mutations_per_payload,
            "max_mutations_per_field": args.max_mutations_per_field,
            **_stability_report_metadata(args, budget),
            **_auth_report_metadata(auth_profile),
            **_config_report_metadata(args),
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
        target_url=args.base_url,
        preset=getattr(args, "preset", None),
    )
    print(
        "GraphQL discovery and payload generation succeeded. "
        f"Generated {metrics.valid_payloads_generated} valid GraphQL payloads. "
        f"planned={execution_bundle.planned_count}, executed={execution_bundle.executed_count}, "
        f"responses={len(execution_bundle.response_records)}, dry_run={bool(args.dry_run)}."
    )
    return 0
