"""Command-line interface for the YSLFuzz MVP pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import ValidationError

from yslfuzz import __version__
from yslfuzz.analysis import AnalysisConfig, AnalysisEngine, FindingBuilder
from yslfuzz.auth import AuthInjector, AuthResolutionError, AuthResolver
from yslfuzz.benchmark import BenchmarkConfigLoader, BenchmarkRunner
from yslfuzz.config import (
    ConfigHasher,
    ConfigLoadError,
    ConfigMerger,
    ConfigValidationError,
    ConfigValidator,
    ScanConfig,
    ScanConfigLoader,
)
from yslfuzz.discovery import OpenAPIParseError, OpenAPIParser
from yslfuzz.discovery.graphql import (
    GraphQLIntrospectionParseError,
    GraphQLSDLParseError,
    GraphQLSchemaLoadError,
    GraphQLSchemaLoader,
    GraphQLToApiSchemaMapper,
)
from yslfuzz.evaluation import (
    EvaluationExporter,
    EvaluationMetricsCalculator,
    FindingMatcher,
    GroundTruthLoader,
)
from yslfuzz.execution import (
    AttackExecutionConfig,
    AttackExecutionPlanner,
    AttackExecutor,
    DestructiveMethodBlockedError,
    HttpExecutor,
    RequestBuilder,
    RequestBuildError,
    ScopeValidator,
    ScopeViolationError,
)
from yslfuzz.labs import LabCatalog
from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    AuthCredentialRef,
    AuthProfile,
    AuthType,
    ExecutionResult,
    FindingConfidence,
    HttpMethod,
    Protocol,
    RequestRecord,
    ResponseRecord,
    ResolvedAuthMaterial,
    ScanRun,
    ScopeDefinition,
    Target,
)
from yslfuzz.models.base import utc_now
from yslfuzz.models.evaluation import EvaluationReport
from yslfuzz.models.enums import PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Endpoint
from yslfuzz.payloads import (
    AttackGenerationConfig,
    AttackPayloadGenerator,
    GraphQLPayloadConfig,
    GraphQLPayloadGenerator,
    MutationConfig,
    MutationEngine,
    PayloadGenerator,
)
from yslfuzz.reporting import JsonReporter, MetricsCalculator


DESTRUCTIVE_METHODS = {HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH}


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level YSLFuzz argument parser."""
    parser = argparse.ArgumentParser(
        prog="yslfuzz",
        description="YSLFuzz schema-aware API fuzzing MVP",
    )
    parser.add_argument("--version", action="version", version=f"yslfuzz {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run the REST/OpenAPI MVP scan pipeline",
        description="Run the REST/OpenAPI MVP scan pipeline",
    )
    scan_parser.add_argument("--config", default=None, help="JSON/YAML scan configuration file")
    schema_group = scan_parser.add_mutually_exclusive_group()
    schema_group.add_argument("--openapi", default=None, help="Local OpenAPI YAML/JSON file")
    schema_group.add_argument(
        "--graphql-schema",
        default=None,
        help="Local GraphQL SDL (.graphql/.gql) or introspection JSON file",
    )
    scan_parser.add_argument("--base-url", default=None, help="Target base URL")
    scan_parser.add_argument("--output", default=None, help="JSON report output path")
    scan_parser.add_argument("--max-requests", type=int, default=None, help="Maximum requests to build")
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds",
    )
    scan_parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="Allow DELETE, PUT and PATCH execution",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse schema and generate payloads without executing requests",
    )
    scan_parser.add_argument("--verbose", action="store_true", help="Print additional scan details")
    scan_parser.add_argument(
        "--include-attack-payloads",
        action="store_true",
        help="Generate safe attack payloads in addition to valid payloads",
    )
    scan_parser.add_argument(
        "--execute-attacks",
        action="store_true",
        help="Execute generated attack payloads; requires explicit authorization flag",
    )
    scan_parser.add_argument(
        "--attack-category",
        action="append",
        default=[],
        help="Attack category to include; may be repeated",
    )
    scan_parser.add_argument(
        "--max-attack-requests-per-endpoint",
        type=int,
        default=5,
        help="Maximum attack requests to execute per endpoint",
    )
    scan_parser.add_argument(
        "--i-understand-this-is-authorized",
        action="store_true",
        help="Required acknowledgement for opt-in attack execution",
    )
    scan_parser.add_argument(
        "--no-deduplicate-findings",
        action="store_true",
        help="Disable default finding deduplication",
    )
    scan_parser.add_argument(
        "--disable-detector",
        action="append",
        default=[],
        help="Disable one analysis detector by stable name or detector id; may be repeated",
    )
    scan_parser.add_argument(
        "--analysis-min-confidence",
        default=None,
        help="Only emit detector results and findings at or above LOW, MEDIUM, HIGH or CONFIRMED",
    )
    scan_parser.add_argument(
        "--include-boundary-payloads",
        action="store_true",
        help="Generate BOUNDARY payloads using MutationEngine",
    )
    scan_parser.add_argument(
        "--include-invalid-payloads",
        action="store_true",
        help="Generate INVALID payloads using MutationEngine",
    )
    scan_parser.add_argument(
        "--include-mutated-payloads",
        action="store_true",
        help="Generate MUTATED payloads using MutationEngine",
    )
    scan_parser.add_argument(
        "--max-mutations-per-payload",
        type=int,
        default=50,
        help="Maximum mutations per base valid payload",
    )
    scan_parser.add_argument(
        "--max-mutations-per-field",
        type=int,
        default=4,
        help="Maximum mutations per field",
    )
    scan_parser.add_argument(
        "--mutate-sensitive-fields",
        action="store_true",
        help="Allow mutation of sensitive fields",
    )
    scan_parser.add_argument(
        "--allow-invalid-enum-values",
        action="store_true",
        help="Allow enum values outside schema enum",
    )
    scan_parser.add_argument(
        "--disable-type-confusion",
        action="store_true",
        help="Disable type-confusion mutations",
    )
    scan_parser.add_argument(
        "--disable-boundary-values",
        action="store_true",
        help="Disable boundary-value mutations",
    )
    scan_parser.add_argument(
        "--disable-null-mutations",
        action="store_true",
        help="Disable null mutations",
    )
    scan_parser.add_argument(
        "--execute-mutations",
        action="store_true",
        help="Execute BOUNDARY, INVALID and MUTATED payloads",
    )
    scan_parser.add_argument(
        "--i-understand-mutation-execution-is-authorized",
        action="store_true",
        help="Required acknowledgement for opt-in mutation execution",
    )
    scan_parser.add_argument(
        "--auth-bearer-env",
        default=None,
        help="Use a bearer token from ENV_VAR",
    )
    scan_parser.add_argument(
        "--auth-api-key-env",
        default=None,
        help="Use an API key from ENV_VAR",
    )
    scan_parser.add_argument(
        "--auth-api-key-header",
        default="X-API-Key",
        help="Header name for --auth-api-key-env",
    )
    scan_parser.add_argument(
        "--auth-cookie-env",
        default=None,
        help="Use a cookie value from ENV_VAR",
    )
    scan_parser.add_argument(
        "--auth-cookie-name",
        default="session",
        help="Cookie name for --auth-cookie-env",
    )
    scan_parser.add_argument(
        "--auth-header",
        action="append",
        default=[],
        help="Custom auth header mapping HEADER_NAME:ENV_VAR; may be repeated",
    )
    scan_parser.add_argument(
        "--graphql-max-selection-depth",
        type=int,
        default=2,
        help="Maximum GraphQL valid payload selection depth",
    )
    scan_parser.add_argument(
        "--graphql-max-fields-per-selection",
        type=int,
        default=5,
        help="Maximum fields selected in each GraphQL selection set",
    )
    scan_parser.add_argument(
        "--graphql-include-mutations",
        action="store_true",
        help="Include GraphQL mutation operations in generated valid payloads",
    )
    scan_parser.add_argument(
        "--graphql-queries-only",
        action="store_true",
        help="Generate GraphQL query payloads only",
    )
    scan_parser.add_argument(
        "--graphql-mutations-only",
        action="store_true",
        help="Generate GraphQL mutation payloads only",
    )
    scan_parser.add_argument(
        "--graphql-max-operations",
        type=int,
        default=None,
        help="Maximum GraphQL operation payloads to generate",
    )
    scan_parser.set_defaults(func=run_scan_command)

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Compare an existing YSLFuzz JSON report with ground truth",
        description="Compare an existing YSLFuzz JSON report with ground truth",
    )
    evaluate_parser.add_argument("--report", required=True, help="Existing YSLFuzz JSON report")
    evaluate_parser.add_argument("--ground-truth", required=True, help="Ground-truth JSON/YAML file")
    evaluate_parser.add_argument("--output-dir", required=True, help="Evaluation output directory")
    evaluate_parser.set_defaults(func=run_evaluate_command)

    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run a benchmark configuration",
        description="Run a benchmark configuration",
    )
    benchmark_parser.add_argument("--config", required=True, help="Benchmark JSON/YAML config path")
    benchmark_parser.add_argument("--output-dir", required=True, help="Benchmark output directory")
    benchmark_parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failed benchmark job",
    )
    benchmark_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force dry-run mode for every benchmark job",
    )
    benchmark_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow writing into an existing benchmark output directory",
    )
    benchmark_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print benchmark job progress",
    )
    benchmark_parser.set_defaults(func=run_benchmark_command)

    labs_parser = subparsers.add_parser(
        "labs",
        help="List and inspect local lab packs",
        description="List and inspect local lab packs without running scans or benchmarks",
    )
    labs_parser.add_argument(
        "--root",
        default=None,
        help="Lab catalog root directory; defaults to examples/labs",
    )
    labs_subparsers = labs_parser.add_subparsers(dest="labs_command", required=True)
    labs_list_parser = labs_subparsers.add_parser("list", help="List available lab packs")
    labs_list_parser.set_defaults(func=run_labs_command)
    labs_show_parser = labs_subparsers.add_parser("show", help="Show one lab pack manifest")
    labs_show_parser.add_argument("--lab", required=True, help="Lab ID to show")
    labs_show_parser.set_defaults(func=run_labs_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the YSLFuzz CLI."""
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(raw_argv)
    args._provided_options = _provided_options(raw_argv)
    if args.command == "scan" and args.config is None:
        schema_supplied = args.openapi is not None or args.graphql_schema is not None
        missing = [
            option
            for option, value in (
                ("--openapi or --graphql-schema", schema_supplied),
                ("--base-url", args.base_url),
                ("--output", args.output),
            )
            if not value
        ]
        if missing:
            parser.error(f"the following arguments are required: {', '.join(missing)}")
    try:
        return int(args.func(args))
    except (
        AuthResolutionError,
        ConfigLoadError,
        ConfigValidationError,
        GraphQLIntrospectionParseError,
        GraphQLSDLParseError,
        GraphQLSchemaLoadError,
        OpenAPIParseError,
        RequestBuildError,
        ScopeViolationError,
        ValidationError,
        ValueError,
    ) as exc:
        parser.exit(1, f"yslfuzz: error: {exc}\n")
    except OSError as exc:
        parser.exit(1, f"yslfuzz: error: {exc}\n")
    return 0


def run_scan_command(args: argparse.Namespace) -> int:
    """Run the scan command and return a process exit code."""
    args = _effective_scan_args(args)
    openapi_arg = getattr(args, "openapi", None)
    graphql_schema_arg = getattr(args, "graphql_schema", None)
    if bool(openapi_arg) == bool(graphql_schema_arg):
        raise ValueError("configure exactly one of --openapi or --graphql-schema")
    if graphql_schema_arg is not None:
        return _run_graphql_discovery_command(args)
    if not isinstance(openapi_arg, str):
        raise ValueError("--openapi must be a local file path")
    openapi_path = Path(openapi_arg)
    if not openapi_path.is_file():
        raise FileNotFoundError(f"OpenAPI file does not exist: {openapi_path}")
    if args.max_requests is not None and args.max_requests < 0:
        raise ValueError("--max-requests must be greater than or equal to 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if args.max_attack_requests_per_endpoint < 0:
        raise ValueError("--max-attack-requests-per-endpoint must be greater than or equal to 0")
    if args.max_mutations_per_payload < 0:
        raise ValueError("--max-mutations-per-payload must be greater than or equal to 0")
    if args.max_mutations_per_field < 0:
        raise ValueError("--max-mutations-per-field must be greater than or equal to 0")
    if args.execute_attacks and not args.i_understand_this_is_authorized:
        raise ValueError("--execute-attacks requires --i-understand-this-is-authorized")
    if args.execute_mutations and not args.i_understand_mutation_execution_is_authorized:
        raise ValueError(
            "--execute-mutations requires --i-understand-mutation-execution-is-authorized"
        )

    api_schema = OpenAPIParser().parse(openapi_path)
    auth_profile = _auth_profile_from_args(args)
    auth_material = AuthResolver().resolve(auth_profile) if auth_profile is not None else None
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
    executor = HttpExecutor()
    attack_executor = AttackExecutor(request_builder, scope_validator)
    analysis_engine = AnalysisEngine(
        config=analysis_config,
        finding_builder=FindingBuilder(deduplicate=not bool(args.no_deduplicate_findings))
    )
    total_detector_results = 0
    total_raw_findings = 0

    for endpoint in api_schema.endpoints:
        if _request_limit_reached(len(requests), args.max_requests):
            break
        if endpoint.method is None:
            continue
        if endpoint.method in DESTRUCTIVE_METHODS and not args.allow_destructive:
            _verbose(args.verbose, f"Skipping destructive endpoint {endpoint.method.value} {endpoint.path}")
            continue

        payload = PayloadGenerator(seed=0).generate_for_endpoint(endpoint)
        payloads.append(payload)
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
        baseline_request = request_record

        if args.dry_run:
            mutation_payloads = _mutation_payloads(endpoint, payload, mutation_config)
            payloads.extend(mutation_payloads)
            if args.include_attack_payloads:
                payloads.extend(_attack_payloads(endpoint, payload, attack_categories))
            continue

        result = _execute_request(
            executor,
            request_record,
            scan_run_id=scan.scan_run_id,
            timeout_seconds=args.timeout,
            auth_material=auth_material,
        )
        execution_results.append(result)
        if result.response_id is not None and result.response_id in executor.response_records:
            baseline_response = executor.response_records[result.response_id]
            responses.append(baseline_response)

        if args.include_attack_payloads:
            generated_attacks = _attack_payloads(endpoint, payload, attack_categories)
            payloads.extend(generated_attacks)
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

        mutation_payloads = _mutation_payloads(endpoint, payload, mutation_config)
        payloads.extend(mutation_payloads)
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
            **_auth_report_metadata(auth_profile),
            **_config_report_metadata(args),
        },
    )
    output_path = JsonReporter().write_json(report, args.output)

    _print_summary(
        output_path=output_path,
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
    )
    return 0


def _run_graphql_discovery_command(args: argparse.Namespace) -> int:
    graphql_schema_path = Path(args.graphql_schema)
    if not graphql_schema_path.is_file():
        raise FileNotFoundError(f"GraphQL schema file does not exist: {graphql_schema_path}")
    if args.max_requests is not None and args.max_requests < 0:
        raise ValueError("--max-requests must be greater than or equal to 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    graphql_payload_config = _graphql_payload_config_from_args(args)

    loader = GraphQLSchemaLoader()
    graphql_schema = loader.load(graphql_schema_path)
    api_schema = GraphQLToApiSchemaMapper().map(graphql_schema, base_url=args.base_url)
    payloads = GraphQLPayloadGenerator(graphql_payload_config).generate(graphql_schema)
    target = _target_from_args(
        args.base_url,
        args.allow_destructive,
        args.max_requests,
        api_style=ApiStyle.GRAPHQL,
    )
    if getattr(args, "target_name", None):
        target.name = args.target_name
    auth_profile = _auth_profile_from_args(args)
    target.auth_profile = auth_profile
    scan = ScanRun(
        project_id="project_cli",
        target_id=target.target_id,
        scan_config_id="scan_config_cli",
        api_schema_id=api_schema.api_schema_id,
    )
    metrics = MetricsCalculator().calculate(
        scan_run_id=scan.scan_run_id,
        endpoints=api_schema.endpoints,
        payloads=payloads,
        requests=[],
        responses=[],
        execution_results=[],
        findings=[],
    )
    report = JsonReporter().build_report(
        scan,
        api_schema=api_schema,
        payloads=payloads,
        requests=[],
        responses=[],
        execution_results=[],
        findings=[],
        target=target,
        metrics=metrics,
        metadata={
            "dry_run": True,
            "api_style": "graphql",
            "graphql_discovery_only": False,
            "graphql_discovery_summary": graphql_schema.discovery_summary(),
            "graphql_payload_generation_implemented": True,
            "graphql_payload_generation": _graphql_payload_generation_summary(
                graphql_schema,
                payloads,
                graphql_payload_config,
            ),
            "scan_status_message": (
                "GraphQL discovery and valid payload generation succeeded. "
                "GraphQL execution is not implemented until Milestone 21."
            ),
            "include_attack_payloads": False,
            "execute_attacks": False,
            "attack_execution_enabled": False,
            "enabled_attack_categories": [],
            "total_detector_results": 0,
            "total_raw_findings": 0,
            "total_deduplicated_findings": 0,
            "deduplicate_findings": not bool(args.no_deduplicate_findings),
            "analysis_config": _analysis_config_from_args(args).summary(),
            "analysis_detectors": [],
            "mutation_execution_enabled": False,
            "mutation_config": _mutation_config_from_args(args).model_dump(mode="json"),
            "random_seed": graphql_payload_config.seed,
            "max_mutations_per_payload": args.max_mutations_per_payload,
            "max_mutations_per_field": args.max_mutations_per_field,
            **_auth_report_metadata(auth_profile),
            **_config_report_metadata(args),
        },
    )
    output_path = JsonReporter().write_json(report, args.output)

    _print_summary(
        output_path=output_path,
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
        dry_run=True,
    )
    print(
        "GraphQL discovery and payload generation succeeded. "
        f"Generated {metrics.valid_payloads_generated} valid GraphQL payloads. "
        "GraphQL execution is not implemented until Milestone 21; executed zero HTTP requests."
    )
    return 0


def run_evaluate_command(args: argparse.Namespace) -> int:
    """Run the evaluation command and return a process exit code."""
    report_path = Path(args.report)
    ground_truth_path = Path(args.ground_truth)
    output_dir = Path(args.output_dir)
    if not report_path.is_file():
        raise FileNotFoundError(f"Report file does not exist: {report_path}")
    if not ground_truth_path.is_file():
        raise FileNotFoundError(f"Ground-truth file does not exist: {ground_truth_path}")

    report = _load_report_dict(report_path)
    ground_truth = GroundTruthLoader().load(ground_truth_path)
    matches = FindingMatcher().match(report, ground_truth)
    metrics = EvaluationMetricsCalculator().calculate(matches, report, ground_truth)
    evaluation_report = EvaluationReport(
        scan_run_id=metrics.scan_run_id,
        lab=ground_truth,
        metrics=metrics,
        matches=matches,
        reproducibility=_evaluation_reproducibility(report, ground_truth),
    )
    paths = EvaluationExporter().write_all(
        evaluation_report,
        output_dir,
        source_report=report,
    )
    print(
        "YSLFuzz evaluation complete: "
        f"scan_run_id={metrics.scan_run_id}, lab_id={metrics.lab_id}, "
        f"tp={metrics.true_positives}, fp={metrics.false_positives}, "
        f"fn={metrics.false_negatives}, precision={metrics.precision}, "
        f"recall={metrics.recall}, f1={metrics.f1_score}, "
        f"output_dir={paths['json'].parent}"
    )
    return 0


def run_benchmark_command(args: argparse.Namespace) -> int:
    """Run the benchmark command and return a process exit code."""
    config = BenchmarkConfigLoader().load(args.config)
    result = BenchmarkRunner(
        config,
        args.output_dir,
        fail_fast=bool(args.fail_fast),
        force_dry_run=bool(args.dry_run),
        overwrite=bool(args.overwrite),
        verbose=bool(args.verbose),
    ).run()
    failed_jobs = sum(1 for job in result.jobs if job.status == "failed")
    print(
        "YSLFuzz benchmark complete: "
        f"benchmark_id={result.benchmark_id}, jobs={len(result.jobs)}, "
        f"failed={failed_jobs}, status={result.status}, output_dir={args.output_dir}"
    )
    return 1 if result.status == "failed" else 0


def run_labs_command(args: argparse.Namespace) -> int:
    """Run the labs catalog command and return a process exit code."""
    manifests = LabCatalog.discover(args.root)
    if args.labs_command == "list":
        for manifest in manifests:
            print(
                f"{manifest.lab_id}\t{manifest.lab_name}\t"
                f"{manifest.lab_version}\t{manifest.api_style.value}"
            )
        return 0

    lab_id = args.lab
    for manifest in manifests:
        if manifest.lab_id == lab_id:
            print(json.dumps(manifest.catalog_summary(), indent=2, sort_keys=True))
            return 0
    raise ValueError(f"Unknown lab: {lab_id}")


def _provided_options(argv: Sequence[str]) -> set[str]:
    options: set[str] = set()
    for item in argv:
        if item.startswith("--"):
            options.add(item.split("=", 1)[0])
    return options


def _effective_scan_args(args: argparse.Namespace) -> argparse.Namespace:
    config_path = getattr(args, "config", None)
    if config_path is None:
        args._config_file_used = False
        args._config_hash = None
        args._scan_config = None
        return args

    config = ScanConfigLoader().load(config_path)
    overrides = _config_overrides_from_args(args, getattr(args, "_provided_options", set()))
    merged_config = ConfigMerger().merge(config, overrides)
    ConfigValidator().validate(merged_config)
    config_hash = ConfigHasher().hash(merged_config)
    return _args_from_scan_config(args, merged_config, config_hash)


def _config_overrides_from_args(
    args: argparse.Namespace,
    provided_options: set[str],
) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    _set_override(overrides, "target", "openapi_path", "--openapi", args.openapi, provided_options)
    _set_override(
        overrides,
        "target",
        "graphql_schema_path",
        "--graphql-schema",
        args.graphql_schema,
        provided_options,
    )
    if "--graphql-schema" in provided_options:
        overrides.setdefault("target", {})["api_style"] = ApiStyle.GRAPHQL.value
        overrides.setdefault("target", {})["openapi_path"] = None
    if "--openapi" in provided_options:
        overrides.setdefault("target", {})["api_style"] = ApiStyle.REST.value
        overrides.setdefault("target", {})["graphql_schema_path"] = None
    _set_override(overrides, "target", "base_url", "--base-url", args.base_url, provided_options)
    _set_override(
        overrides,
        "reporting",
        "output",
        "--output",
        args.output,
        provided_options,
    )
    _set_override(
        overrides,
        "execution",
        "max_requests",
        "--max-requests",
        args.max_requests,
        provided_options,
    )
    _set_override(overrides, "execution", "timeout", "--timeout", args.timeout, provided_options)

    for option, key in (
        ("--allow-destructive", "allow_destructive"),
        ("--dry-run", "dry_run"),
        ("--execute-mutations", "execute_mutations"),
        ("--execute-attacks", "execute_attacks"),
        ("--i-understand-this-is-authorized", "i_understand_attack_execution_is_authorized"),
        (
            "--i-understand-mutation-execution-is-authorized",
            "i_understand_mutation_execution_is_authorized",
        ),
    ):
        if option in provided_options:
            overrides.setdefault("execution", {})[key] = True

    for option, key in (
        ("--include-boundary-payloads", "include_boundary_payloads"),
        ("--include-invalid-payloads", "include_invalid_payloads"),
        ("--include-mutated-payloads", "include_mutated_payloads"),
        ("--include-attack-payloads", "include_attack_payloads"),
        ("--mutate-sensitive-fields", "mutate_sensitive_fields"),
        ("--allow-invalid-enum-values", "allow_invalid_enum_values"),
        ("--disable-type-confusion", "disable_type_confusion"),
        ("--disable-boundary-values", "disable_boundary_values"),
        ("--disable-null-mutations", "disable_null_mutations"),
    ):
        if option in provided_options:
            overrides.setdefault("payloads", {})[key] = True

    _set_override(
        overrides,
        "payloads",
        "max_mutations_per_payload",
        "--max-mutations-per-payload",
        args.max_mutations_per_payload,
        provided_options,
    )
    _set_override(
        overrides,
        "payloads",
        "max_mutations_per_field",
        "--max-mutations-per-field",
        args.max_mutations_per_field,
        provided_options,
    )
    _set_override(
        overrides,
        "payloads",
        "max_attack_requests_per_endpoint",
        "--max-attack-requests-per-endpoint",
        args.max_attack_requests_per_endpoint,
        provided_options,
    )
    _set_override(
        overrides,
        "payloads",
        "graphql_max_selection_depth",
        "--graphql-max-selection-depth",
        args.graphql_max_selection_depth,
        provided_options,
    )
    _set_override(
        overrides,
        "payloads",
        "graphql_max_fields_per_selection",
        "--graphql-max-fields-per-selection",
        args.graphql_max_fields_per_selection,
        provided_options,
    )
    _set_override(
        overrides,
        "payloads",
        "graphql_max_operations",
        "--graphql-max-operations",
        args.graphql_max_operations,
        provided_options,
    )
    if "--graphql-include-mutations" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = True
    if "--graphql-queries-only" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_queries"] = True
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = False
    if "--graphql-mutations-only" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_queries"] = False
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = True
    if "--attack-category" in provided_options:
        overrides.setdefault("payloads", {})["enabled_attack_categories"] = [
            str(category).upper() for category in args.attack_category
        ]

    if "--disable-detector" in provided_options:
        overrides.setdefault("analysis", {})["disabled_detectors"] = list(args.disable_detector)
    if "--analysis-min-confidence" in provided_options:
        overrides.setdefault("analysis", {})["analysis_min_confidence"] = str(
            args.analysis_min_confidence
        ).upper()

    auth_overrides = _auth_overrides_from_args(args, provided_options)
    if auth_overrides:
        overrides["auth"] = auth_overrides

    return overrides


def _set_override(
    overrides: dict[str, Any],
    section: str,
    key: str,
    option: str,
    value: Any,
    provided_options: set[str],
) -> None:
    if option in provided_options:
        overrides.setdefault(section, {})[key] = value


def _auth_overrides_from_args(
    args: argparse.Namespace,
    provided_options: set[str],
) -> dict[str, Any]:
    mode_options = {
        "--auth-bearer-env",
        "--auth-api-key-env",
        "--auth-cookie-env",
        "--auth-header",
    }
    name_only_options = {"--auth-api-key-header", "--auth-cookie-name"}
    if not (provided_options & (mode_options | name_only_options)):
        return {}

    if "--auth-bearer-env" in provided_options:
        return _auth_override_base(bearer_env=args.auth_bearer_env)
    if "--auth-api-key-env" in provided_options:
        return _auth_override_base(
            api_key_env=args.auth_api_key_env,
            api_key_header=args.auth_api_key_header,
        )
    if "--auth-cookie-env" in provided_options:
        return _auth_override_base(
            cookie_env=args.auth_cookie_env,
            cookie_name=args.auth_cookie_name,
        )
    if "--auth-header" in provided_options:
        return _auth_override_base(custom_headers=list(args.auth_header or []))

    auth: dict[str, Any] = {}
    if "--auth-api-key-header" in provided_options:
        auth["api_key_header"] = args.auth_api_key_header
    if "--auth-cookie-name" in provided_options:
        auth["cookie_name"] = args.auth_cookie_name
    return auth


def _auth_override_base(
    *,
    bearer_env: str | None = None,
    api_key_env: str | None = None,
    api_key_header: str = "X-API-Key",
    cookie_env: str | None = None,
    cookie_name: str = "session",
    custom_headers: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "bearer_env": bearer_env,
        "api_key_env": api_key_env,
        "api_key_header": api_key_header,
        "cookie_env": cookie_env,
        "cookie_name": cookie_name,
        "custom_headers": custom_headers or [],
    }


def _args_from_scan_config(
    args: argparse.Namespace,
    config: ScanConfig,
    config_hash: str,
) -> argparse.Namespace:
    effective = argparse.Namespace(**vars(args))
    effective.openapi = config.target.openapi_path
    effective.graphql_schema = config.target.graphql_schema_path
    effective.base_url = config.target.base_url
    effective.target_name = config.target.target_name
    effective.output = config.reporting.output
    effective.max_requests = config.execution.max_requests
    effective.timeout = config.execution.timeout
    effective.allow_destructive = config.execution.allow_destructive
    effective.dry_run = config.execution.dry_run
    effective.include_boundary_payloads = config.payloads.include_boundary_payloads
    effective.include_invalid_payloads = config.payloads.include_invalid_payloads
    effective.include_mutated_payloads = config.payloads.include_mutated_payloads
    effective.include_attack_payloads = config.payloads.include_attack_payloads
    effective.execute_mutations = config.execution.execute_mutations
    effective.execute_attacks = config.execution.execute_attacks
    effective.attack_category = [
        category.value for category in config.payloads.enabled_attack_categories
    ]
    effective.max_mutations_per_payload = config.payloads.max_mutations_per_payload
    effective.max_mutations_per_field = config.payloads.max_mutations_per_field
    effective.max_attack_requests_per_endpoint = config.payloads.max_attack_requests_per_endpoint
    effective.graphql_max_selection_depth = config.payloads.graphql_max_selection_depth
    effective.graphql_max_fields_per_selection = config.payloads.graphql_max_fields_per_selection
    effective.graphql_max_operations = config.payloads.graphql_max_operations
    effective.graphql_include_mutations = config.payloads.graphql_include_mutations
    effective.graphql_queries_only = (
        config.payloads.graphql_include_queries and not config.payloads.graphql_include_mutations
    )
    effective.graphql_mutations_only = (
        config.payloads.graphql_include_mutations and not config.payloads.graphql_include_queries
    )
    effective.mutate_sensitive_fields = config.payloads.mutate_sensitive_fields
    effective.allow_invalid_enum_values = config.payloads.allow_invalid_enum_values
    effective.disable_type_confusion = config.payloads.disable_type_confusion
    effective.disable_boundary_values = config.payloads.disable_boundary_values
    effective.disable_null_mutations = config.payloads.disable_null_mutations
    effective.i_understand_this_is_authorized = (
        config.execution.i_understand_attack_execution_is_authorized
    )
    effective.i_understand_mutation_execution_is_authorized = (
        config.execution.i_understand_mutation_execution_is_authorized
    )
    effective.disable_detector = list(config.analysis.disabled_detectors)
    effective.analysis_min_confidence = (
        config.analysis.analysis_min_confidence.value
        if config.analysis.analysis_min_confidence is not None
        else None
    )
    effective.auth_bearer_env = config.auth.bearer_env
    effective.auth_api_key_env = config.auth.api_key_env
    effective.auth_api_key_header = config.auth.api_key_header
    effective.auth_cookie_env = config.auth.cookie_env
    effective.auth_cookie_name = config.auth.cookie_name
    effective.auth_header = list(config.auth.custom_headers)
    effective._config_file_used = True
    effective._scan_config = config
    effective._config_hash = config_hash
    return effective


def _config_report_metadata(args: argparse.Namespace) -> dict[str, Any]:
    config = getattr(args, "_scan_config", None)
    if config is None:
        return {
            "config_file_used": False,
            "config_profile_name": None,
            "config_hash": None,
            "config_loaded_at": None,
            "config_enabled_modes": {},
        }
    return {
        "config_file_used": True,
        "config_profile_name": config.metadata.scan_name,
        "config_hash": getattr(args, "_config_hash", None),
        "config_loaded_at": config.config_loaded_at,
        "config_enabled_modes": config.safe_enabled_modes_summary(),
    }


def _load_report_dict(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Report root must be a JSON object")
    return data


def _evaluation_reproducibility(
    report: dict[str, object],
    ground_truth: object,
) -> dict[str, object]:
    reproducibility = report.get("reproducibility", {})
    if not isinstance(reproducibility, dict):
        reproducibility = {}
    analysis_summary = report.get("analysis_summary")
    detector_list: object = []
    if isinstance(analysis_summary, dict):
        detector_list = analysis_summary.get("detectors", [])
    lab_id = getattr(ground_truth, "lab_id", None)
    lab_version = getattr(ground_truth, "lab_version", None)
    return {
        "yslfuzz_version": __version__,
        "report_schema_version": report.get("report_schema_version"),
        "scan_run_id": report.get("scan_run_id"),
        "lab_id": lab_id,
        "lab_version": lab_version,
        "random_seed": reproducibility.get("random_seed"),
        "generated_at": report.get("generated_at"),
        "evaluation_generated_at": utc_now().isoformat(),
        "detectors": detector_list or reproducibility.get("detectors", []),
        "enabled_payload_modes": reproducibility.get("enabled_payload_modes", []),
        "attack_execution_enabled": bool(reproducibility.get("attack_execution_enabled", False)),
        "mutation_execution_enabled": bool(reproducibility.get("mutation_execution_enabled", False)),
    }


def _target_from_args(
    base_url: str,
    allow_destructive: bool,
    max_requests: int | None,
    *,
    api_style: ApiStyle = ApiStyle.REST,
) -> Target:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("--base-url must be a valid HTTP or HTTPS URL")

    allowed_methods = [HttpMethod.GET, HttpMethod.POST, HttpMethod.HEAD, HttpMethod.OPTIONS]
    if allow_destructive:
        allowed_methods.extend([HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH])

    protocol = Protocol.HTTPS if parsed.scheme == "https" else Protocol.HTTP
    return Target(
        name=parsed.hostname,
        base_url=base_url,
        api_style=api_style,
        protocol=protocol,
        scope=ScopeDefinition(
            allowed_hosts=[parsed.hostname],
            max_requests=max_requests,
            allow_destructive_methods=allow_destructive,
            allowed_methods=allowed_methods,
        ),
    )


def _attack_categories_from_args(category_names: Sequence[str]) -> list[AttackCategory]:
    categories: list[AttackCategory] = []
    for name in category_names:
        normalized = name.upper()
        try:
            categories.append(AttackCategory(normalized))
        except ValueError as exc:
            raise ValueError(f"Unsupported --attack-category: {name}") from exc
    return categories


def _attack_payloads(
    endpoint: Endpoint,
    valid_payload: PayloadCandidate,
    categories: Sequence[AttackCategory],
) -> list[PayloadCandidate]:
    config = (
        AttackGenerationConfig(enabled_categories=list(categories))
        if categories
        else AttackGenerationConfig()
    )
    return AttackPayloadGenerator(config).generate(endpoint, valid_payload)


def _mutation_config_from_args(args: argparse.Namespace) -> MutationConfig:
    enabled_payload_kinds: list[PayloadKind] = []
    if args.include_boundary_payloads:
        enabled_payload_kinds.append(PayloadKind.BOUNDARY)
    if args.include_invalid_payloads:
        enabled_payload_kinds.append(PayloadKind.INVALID)
    if args.include_mutated_payloads:
        enabled_payload_kinds.append(PayloadKind.MUTATED)
    return MutationConfig(
        enabled_payload_kinds=enabled_payload_kinds,
        max_mutations_per_payload=args.max_mutations_per_payload,
        max_mutations_per_field=args.max_mutations_per_field,
        include_sensitive_fields=bool(args.mutate_sensitive_fields),
        deterministic=True,
        random_seed=0,
        allow_invalid_enum_values=bool(args.allow_invalid_enum_values),
        allow_type_confusion=not bool(args.disable_type_confusion),
        allow_boundary_values=not bool(args.disable_boundary_values),
        allow_null_mutations=not bool(args.disable_null_mutations),
    )


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
        "note": "GraphQL execution is not implemented until Milestone 21.",
    }


def _analysis_config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    confidence = None
    if args.analysis_min_confidence is not None:
        try:
            confidence = FindingConfidence(args.analysis_min_confidence.upper())
        except ValueError as exc:
            raise ValueError(
                "--analysis-min-confidence must be one of LOW, MEDIUM, HIGH or CONFIRMED"
            ) from exc
    return AnalysisConfig(
        disabled_detectors=list(args.disable_detector),
        minimum_confidence=confidence,
    )


def _auth_profile_from_args(args: argparse.Namespace) -> AuthProfile | None:
    bearer_env = getattr(args, "auth_bearer_env", None)
    api_key_env = getattr(args, "auth_api_key_env", None)
    api_key_header = getattr(args, "auth_api_key_header", "X-API-Key")
    cookie_env = getattr(args, "auth_cookie_env", None)
    cookie_name = getattr(args, "auth_cookie_name", "session")
    custom_headers = list(getattr(args, "auth_header", []) or [])

    configured_modes = sum(
        bool(value)
        for value in (
            bearer_env,
            api_key_env,
            cookie_env,
            custom_headers,
        )
    )
    if configured_modes > 1:
        raise ValueError("conflicting authentication flags: configure only one auth mode per scan")
    if api_key_env is None and api_key_header != "X-API-Key":
        raise ValueError("--auth-api-key-header requires --auth-api-key-env")
    if cookie_env is None and cookie_name != "session":
        raise ValueError("--auth-cookie-name requires --auth-cookie-env")
    if configured_modes == 0:
        return None

    if bearer_env:
        return AuthProfile(
            name="cli-bearer",
            auth_type=AuthType.BEARER,
            credential_ref=AuthCredentialRef(env_var=bearer_env),
        )
    if api_key_env:
        return AuthProfile(
            name="cli-api-key-header",
            auth_type=AuthType.API_KEY,
            credential_ref=AuthCredentialRef(env_var=api_key_env),
            header_name=api_key_header,
        )
    if cookie_env:
        return AuthProfile(
            name="cli-cookie",
            auth_type=AuthType.COOKIE,
            credential_ref=AuthCredentialRef(env_var=cookie_env),
            cookie_name=cookie_name,
        )

    refs = [
        AuthCredentialRef(env_var=env_var, header_name=header_name)
        for header_name, env_var in (_parse_auth_header(value) for value in custom_headers)
    ]
    return AuthProfile(name="cli-custom-header", auth_type=AuthType.CUSTOM, credential_refs=refs)


def _parse_auth_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise ValueError("--auth-header must use HEADER_NAME:ENV_VAR")
    header_name, env_var = value.split(":", 1)
    header_name = header_name.strip()
    env_var = env_var.strip()
    if not header_name or not env_var:
        raise ValueError("--auth-header must include both header name and environment variable name")
    return header_name, env_var


def _auth_report_metadata(profile: AuthProfile | None) -> dict[str, object]:
    if profile is None:
        return {
            "authentication_enabled": False,
            "authentication_types": [],
            "auth_sources": [],
            "auth_redaction_applied": True,
        }
    return profile.redacted_display()


def _execute_request(
    executor: HttpExecutor,
    request_record: RequestRecord,
    *,
    scan_run_id: str,
    timeout_seconds: float,
    auth_material: ResolvedAuthMaterial | None = None,
) -> ExecutionResult:
    if auth_material is None:
        return executor.execute(
            request_record,
            scan_run_id=scan_run_id,
            timeout_seconds=timeout_seconds,
        )
    return executor.execute(
        request_record,
        scan_run_id=scan_run_id,
        timeout_seconds=timeout_seconds,
        auth_material=auth_material,
    )


def _mutation_payloads(
    endpoint: Endpoint,
    valid_payload: PayloadCandidate,
    config: MutationConfig,
) -> list[PayloadCandidate]:
    if not config.enabled_payload_kinds:
        return []
    return MutationEngine(config).mutate(endpoint, valid_payload)


def _execute_payloads(
    *,
    endpoint: Endpoint,
    payloads: Sequence[PayloadCandidate],
    target: Target,
    scan_run_id: str,
    request_builder: RequestBuilder,
    auth_injector: AuthInjector,
    scope_validator: ScopeValidator,
    executor: HttpExecutor,
    timeout_seconds: float,
    max_requests: int | None,
    current_request_count: int,
    auth_material: ResolvedAuthMaterial | None = None,
) -> tuple[list[RequestRecord], list[ResponseRecord], list[ExecutionResult]]:
    requests: list[RequestRecord] = []
    responses: list[ResponseRecord] = []
    execution_results: list[ExecutionResult] = []
    for payload in payloads:
        if _request_limit_reached(current_request_count + len(requests), max_requests):
            break
        request_record = request_builder.build(
            endpoint=endpoint,
            payload=payload,
            target=target,
            scan_run_id=scan_run_id,
        )
        request_record = auth_injector.apply(request_record, auth_material)
        try:
            scope_validator.validate(request_record, target.scope)
        except (DestructiveMethodBlockedError, ScopeViolationError):
            continue
        requests.append(request_record)
        result = _execute_request(
            executor,
            request_record,
            scan_run_id=scan_run_id,
            timeout_seconds=timeout_seconds,
            auth_material=auth_material,
        )
        execution_results.append(result)
        if result.response_id is not None and result.response_id in executor.response_records:
            responses.append(executor.response_records[result.response_id])
    return requests, responses, execution_results


def _request_limit_reached(current_request_count: int, max_requests: int | None) -> bool:
    return max_requests is not None and current_request_count >= max_requests


def _print_summary(
    *,
    output_path: Path,
    total_endpoints: int,
    payloads_generated: int,
    valid_payloads_generated: int,
    boundary_payloads_generated: int,
    invalid_payloads_generated: int,
    mutated_payloads_generated: int,
    attack_payloads_generated: int,
    total_requests: int,
    successful_requests: int,
    failed_requests: int,
    findings_total: int,
    dry_run: bool,
) -> None:
    mode = "dry-run" if dry_run else "executed"
    print(
        "YSLFuzz scan complete "
        f"({mode}): endpoints={total_endpoints}, "
        f"valid_payloads={valid_payloads_generated}, "
        f"boundary_payloads={boundary_payloads_generated}, "
        f"invalid_payloads={invalid_payloads_generated}, "
        f"mutated_payloads={mutated_payloads_generated}, "
        f"attack_payloads={attack_payloads_generated}, "
        f"payloads={payloads_generated}, requests={total_requests}, "
        f"successful={successful_requests}, failed={failed_requests}, "
        f"findings={findings_total}, "
        f"report={output_path}"
    )


def _verbose(enabled: bool, message: str) -> None:
    if enabled:
        print(message)


if __name__ == "__main__":
    raise SystemExit(main())
