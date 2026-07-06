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
    GraphQLExecutionConfig,
    GraphQLExecutor,
    HttpExecutor,
    RequestBuilder,
    RequestBuildError,
    BackoffPolicy,
    ExecutionBudget,
    ProgressTracker,
    RateLimiter,
    RetryPolicy,
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
    ExecutionStatus,
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
from yslfuzz.models.stability import RateLimitConfig, RetryConfig, ScanLimits
from yslfuzz.payloads import (
    AttackGenerationConfig,
    AttackPayloadGenerator,
    GraphQLAttackPayloadGenerator,
    GraphQLMutationConfig,
    GraphQLMutationEngine,
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
    scan_parser.add_argument(
        "--graphql-endpoint",
        default="/graphql",
        help="GraphQL HTTP endpoint path",
    )
    scan_parser.add_argument(
        "--graphql-max-requests",
        type=int,
        default=None,
        help="Maximum GraphQL requests to plan or execute",
    )
    scan_parser.add_argument(
        "--graphql-include-introspection-probe",
        action="store_true",
        help="Include a bounded safe GraphQL introspection probe when attack payloads are enabled",
    )
    scan_parser.add_argument(
        "--rate-limit-rps",
        type=float,
        default=None,
        help="Approximate maximum HTTP requests per second",
    )
    scan_parser.add_argument(
        "--min-request-delay-ms",
        type=int,
        default=None,
        help="Minimum delay between HTTP requests in milliseconds",
    )
    scan_parser.add_argument(
        "--max-requests-per-endpoint",
        type=int,
        default=None,
        help="Maximum planned requests per endpoint",
    )
    scan_parser.add_argument(
        "--max-scan-duration-seconds",
        type=float,
        default=None,
        help="Global scan duration limit in seconds",
    )
    scan_parser.add_argument(
        "--retry",
        action="store_true",
        help="Enable conservative retry policy",
    )
    scan_parser.add_argument(
        "--max-retries",
        type=int,
        default=0,
        help="Maximum retry attempts when --retry is enabled",
    )
    scan_parser.add_argument(
        "--retry-status-code",
        action="append",
        default=[],
        help="HTTP status code to retry; may be repeated or comma-separated",
    )
    scan_parser.add_argument(
        "--backoff-initial-ms",
        type=int,
        default=100,
        help="Initial retry backoff in milliseconds",
    )
    scan_parser.add_argument(
        "--backoff-max-ms",
        type=int,
        default=2000,
        help="Maximum retry backoff in milliseconds",
    )
    scan_parser.add_argument(
        "--progress",
        action="store_true",
        help="Print concise scan progress when verbose output is enabled",
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
    budget = ExecutionBudget(_scan_limits_from_args(args, api_style=ApiStyle.REST))
    progress = ProgressTracker(total_endpoints=len(api_schema.endpoints))
    executor = _http_executor_from_args(args)
    attack_executor = AttackExecutor(request_builder, scope_validator, http_executor=executor)
    analysis_engine = AnalysisEngine(
        config=analysis_config,
        finding_builder=FindingBuilder(deduplicate=not bool(args.no_deduplicate_findings))
    )
    total_detector_results = 0
    total_raw_findings = 0

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
    if args.max_mutations_per_payload < 0:
        raise ValueError("--max-mutations-per-payload must be greater than or equal to 0")
    if args.max_mutations_per_field < 0:
        raise ValueError("--max-mutations-per-field must be greater than or equal to 0")
    if args.max_attack_requests_per_endpoint < 0:
        raise ValueError("--max-attack-requests-per-endpoint must be greater than or equal to 0")
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
    print(
        "GraphQL discovery and payload generation succeeded. "
        f"Generated {metrics.valid_payloads_generated} valid GraphQL payloads. "
        f"planned={execution_bundle.planned_count}, executed={execution_bundle.executed_count}, "
        f"responses={len(execution_bundle.response_records)}, dry_run={bool(args.dry_run)}."
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
    _set_override(
        overrides,
        "limits",
        "max_requests",
        "--max-requests",
        args.max_requests,
        provided_options,
    )
    _set_override(
        overrides,
        "limits",
        "max_requests_per_endpoint",
        "--max-requests-per-endpoint",
        args.max_requests_per_endpoint,
        provided_options,
    )
    _set_override(
        overrides,
        "limits",
        "max_duration_seconds",
        "--max-scan-duration-seconds",
        args.max_scan_duration_seconds,
        provided_options,
    )
    _set_override(overrides, "execution", "timeout", "--timeout", args.timeout, provided_options)
    _set_override(
        overrides,
        "stability",
        "rate_limit_rps",
        "--rate-limit-rps",
        args.rate_limit_rps,
        provided_options,
    )
    _set_override(
        overrides,
        "stability",
        "min_request_delay_ms",
        "--min-request-delay-ms",
        args.min_request_delay_ms,
        provided_options,
    )
    if "--progress" in provided_options:
        overrides.setdefault("stability", {})["progress"] = True
    if "--retry" in provided_options:
        overrides.setdefault("stability", {}).setdefault("retry", {})["enabled"] = True
    if "--max-retries" in provided_options:
        overrides.setdefault("stability", {}).setdefault("retry", {})["max_retries"] = args.max_retries
    if "--retry-status-code" in provided_options:
        overrides.setdefault("stability", {}).setdefault("retry", {})[
            "retry_on_status_codes"
        ] = _retry_status_codes_from_args(args.retry_status_code)
    if "--backoff-initial-ms" in provided_options:
        overrides.setdefault("stability", {}).setdefault("retry", {})[
            "backoff_initial_ms"
        ] = args.backoff_initial_ms
    if "--backoff-max-ms" in provided_options:
        overrides.setdefault("stability", {}).setdefault("retry", {})[
            "backoff_max_ms"
        ] = args.backoff_max_ms

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
        "graphql",
        "max_selection_depth",
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
        "graphql",
        "max_fields_per_selection",
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
    _set_override(
        overrides,
        "graphql",
        "max_operations",
        "--graphql-max-operations",
        args.graphql_max_operations,
        provided_options,
    )
    _set_override(
        overrides,
        "graphql",
        "endpoint_path",
        "--graphql-endpoint",
        args.graphql_endpoint,
        provided_options,
    )
    _set_override(
        overrides,
        "graphql",
        "max_requests",
        "--graphql-max-requests",
        args.graphql_max_requests,
        provided_options,
    )
    if "--graphql-include-introspection-probe" in provided_options:
        overrides.setdefault("graphql", {})["include_introspection_probe"] = True
        overrides.setdefault("payloads", {})["allow_introspection_probe"] = True
    if "--graphql-include-mutations" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = True
        overrides.setdefault("graphql", {})["include_mutations"] = True
    if "--graphql-queries-only" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_queries"] = True
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = False
        overrides.setdefault("graphql", {})["include_queries"] = True
        overrides.setdefault("graphql", {})["include_mutations"] = False
    if "--graphql-mutations-only" in provided_options:
        overrides.setdefault("payloads", {})["graphql_include_queries"] = False
        overrides.setdefault("payloads", {})["graphql_include_mutations"] = True
        overrides.setdefault("graphql", {})["include_queries"] = False
        overrides.setdefault("graphql", {})["include_mutations"] = True
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
    effective.max_requests_per_endpoint = config.limits.max_requests_per_endpoint
    effective.max_scan_duration_seconds = config.limits.max_duration_seconds
    effective.rate_limit_rps = config.stability.rate_limit_rps
    effective.min_request_delay_ms = config.stability.min_request_delay_ms
    effective.retry = config.stability.retry.enabled
    effective.max_retries = config.stability.retry.max_retries
    effective.retry_status_code = list(config.stability.retry.retry_on_status_codes)
    effective.backoff_initial_ms = config.stability.retry.backoff_initial_ms
    effective.backoff_max_ms = config.stability.retry.backoff_max_ms
    effective.progress = config.stability.progress
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
    effective.graphql_max_selection_depth = _graphql_config_value(
        config,
        "max_selection_depth",
        config.payloads.graphql_max_selection_depth,
    )
    effective.graphql_max_fields_per_selection = _graphql_config_value(
        config,
        "max_fields_per_selection",
        config.payloads.graphql_max_fields_per_selection,
    )
    effective.graphql_max_operations = _graphql_config_value(
        config,
        "max_operations",
        config.payloads.graphql_max_operations,
    )
    graphql_include_queries = bool(
        _graphql_config_value(config, "include_queries", config.payloads.graphql_include_queries)
    )
    graphql_include_mutations = bool(
        _graphql_config_value(config, "include_mutations", config.payloads.graphql_include_mutations)
    )
    effective.graphql_include_mutations = graphql_include_mutations
    effective.graphql_queries_only = (
        graphql_include_queries and not graphql_include_mutations
    )
    effective.graphql_mutations_only = (
        graphql_include_mutations and not graphql_include_queries
    )
    effective.graphql_endpoint = config.graphql.endpoint_path
    effective.graphql_max_requests = config.graphql.max_requests
    effective.graphql_execute_graphql = config.graphql.execute_graphql
    effective.graphql_enable_analysis = config.graphql.enable_analysis
    effective.graphql_include_introspection_probe = config.graphql.include_introspection_probe
    effective.mutate_sensitive_fields = config.payloads.mutate_sensitive_fields
    effective.allow_invalid_enum_values = config.payloads.allow_invalid_enum_values
    effective.disable_type_confusion = config.payloads.disable_type_confusion
    effective.disable_boundary_values = config.payloads.disable_boundary_values
    effective.disable_null_mutations = config.payloads.disable_null_mutations
    effective.allow_extra_input_fields = config.payloads.allow_extra_input_fields
    effective.allow_missing_required_fields = config.payloads.allow_missing_required_fields
    effective.allow_introspection_probe = config.payloads.allow_introspection_probe
    if config.graphql.include_introspection_probe:
        effective.allow_introspection_probe = True
    effective.allow_error_leakage_probe = config.payloads.allow_error_leakage_probe
    effective.allow_reflection_probe = config.payloads.allow_reflection_probe
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
    effective.enable_graphql_error_disclosure = config.analysis.enable_graphql_error_disclosure
    effective.enable_graphql_validation_bypass = config.analysis.enable_graphql_validation_bypass
    effective.enable_graphql_introspection_exposure = (
        config.analysis.enable_graphql_introspection_exposure
    )
    effective.enable_graphql_reflection_detection = config.analysis.enable_graphql_reflection_detection
    effective.enable_graphql_mass_assignment_detection = (
        config.analysis.enable_graphql_mass_assignment_detection
    )
    effective.enable_graphql_authorization_consistency = (
        config.analysis.enable_graphql_authorization_consistency
    )
    effective.enable_graphql_injection_marker_detection = (
        config.analysis.enable_graphql_injection_marker_detection
    )
    effective.enable_graphql_ssrf_marker_detection = config.analysis.enable_graphql_ssrf_marker_detection
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


def _graphql_config_value(config: ScanConfig, field_name: str, fallback: Any) -> Any:
    if field_name in config.graphql.model_fields_set:
        return getattr(config.graphql, field_name)
    return fallback


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


def _retry_status_codes_from_args(values: Sequence[object]) -> list[int]:
    """Parse repeated or comma-separated retry status codes."""
    if not values:
        return [429, 500, 502, 503, 504]
    codes: list[int] = []
    for value in values:
        for item in str(value).split(","):
            stripped = item.strip()
            if not stripped:
                continue
            code = int(stripped)
            if code < 100 or code > 599:
                raise ValueError("--retry-status-code must contain valid HTTP status codes")
            codes.append(code)
    return codes or [429, 500, 502, 503, 504]


def _scan_limits_from_args(args: argparse.Namespace, *, api_style: ApiStyle) -> ScanLimits:
    graphql_max_requests = _effective_graphql_request_limit(
        getattr(args, "graphql_max_requests", None),
        getattr(args, "max_requests", None),
    )
    return ScanLimits(
        max_requests=getattr(args, "max_requests", None),
        max_requests_per_endpoint=getattr(args, "max_requests_per_endpoint", None),
        max_duration_seconds=getattr(args, "max_scan_duration_seconds", None),
        max_graphql_operations=getattr(args, "graphql_max_operations", None)
        if api_style == ApiStyle.GRAPHQL
        else None,
        max_graphql_requests=graphql_max_requests if api_style == ApiStyle.GRAPHQL else None,
        max_rest_requests=getattr(args, "max_requests", None) if api_style == ApiStyle.REST else None,
    )


def _rate_limit_config_from_args(args: argparse.Namespace) -> RateLimitConfig:
    return RateLimitConfig(
        requests_per_second=getattr(args, "rate_limit_rps", None),
        min_delay_ms=getattr(args, "min_request_delay_ms", None),
    )


def _retry_config_from_args(args: argparse.Namespace) -> RetryConfig:
    return RetryConfig(
        enabled=bool(getattr(args, "retry", False)),
        max_retries=int(getattr(args, "max_retries", 0) or 0),
        retry_on_status_codes=_retry_status_codes_from_args(
            getattr(args, "retry_status_code", []) or []
        ),
        backoff_initial_ms=int(getattr(args, "backoff_initial_ms", 100) or 100),
        backoff_max_ms=int(getattr(args, "backoff_max_ms", 2000) or 2000),
    )


def _http_executor_from_args(args: argparse.Namespace) -> HttpExecutor:
    rate_config = _rate_limit_config_from_args(args)
    retry_config = _retry_config_from_args(args)
    rate_limiter = (
        RateLimiter(rate_config)
        if rate_config.requests_per_second is not None or rate_config.min_delay_ms is not None
        else None
    )
    try:
        return HttpExecutor(
            rate_limiter=rate_limiter,
            retry_policy=RetryPolicy(retry_config),
            backoff_policy=BackoffPolicy(retry_config),
        )
    except TypeError:
        return HttpExecutor()


def _stability_report_metadata(
    args: argparse.Namespace,
    budget: ExecutionBudget,
    *,
    partial_results: bool = False,
    cancellation_reason: str | None = None,
) -> dict[str, Any]:
    rate_config = _rate_limit_config_from_args(args)
    retry_config = _retry_config_from_args(args)
    timed_out = budget.timed_out() or budget.skipped_due_to_timeout > 0
    scan_status = "timed_out" if timed_out else "partial" if partial_results else "completed"
    finished_at = utc_now()
    started_seconds = budget.started_at_seconds or 0.0
    duration_seconds = 0.0
    if started_seconds:
        from time import monotonic

        duration_seconds = round(max(0.0, monotonic() - started_seconds), 6)
    return {
        "stability": {
            "scan_status": scan_status,
            "max_requests": getattr(args, "max_requests", None),
            "max_requests_per_endpoint": getattr(args, "max_requests_per_endpoint", None),
            "max_duration_seconds": getattr(args, "max_scan_duration_seconds", None),
            "rate_limit_rps": rate_config.requests_per_second,
            "min_request_delay_ms": rate_config.min_delay_ms,
            "retry_enabled": retry_config.enabled,
            "max_retries": retry_config.max_retries,
            "total_retries_attempted": budget.total_retries_attempted,
            "started_at": budget.started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": duration_seconds,
            "partial_results": partial_results or timed_out,
            "cancellation_reason": cancellation_reason,
            **budget.summary(),
        }
    }


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


def _effective_graphql_request_limit(
    graphql_max_requests: int | None,
    max_requests: int | None,
) -> int | None:
    limits = [limit for limit in (graphql_max_requests, max_requests) if limit is not None]
    if not limits:
        return None
    return min(limits)


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
        enable_graphql_error_disclosure=bool(
            getattr(args, "enable_graphql_error_disclosure", True)
        ),
        enable_graphql_validation_bypass=bool(
            getattr(args, "enable_graphql_validation_bypass", True)
        ),
        enable_graphql_introspection_exposure=bool(
            getattr(args, "enable_graphql_introspection_exposure", True)
        ),
        enable_graphql_reflection_detection=bool(
            getattr(args, "enable_graphql_reflection_detection", True)
        ),
        enable_graphql_mass_assignment_detection=bool(
            getattr(args, "enable_graphql_mass_assignment_detection", True)
        ),
        enable_graphql_authorization_consistency=bool(
            getattr(args, "enable_graphql_authorization_consistency", True)
        ),
        enable_graphql_injection_marker_detection=bool(
            getattr(args, "enable_graphql_injection_marker_detection", True)
        ),
        enable_graphql_ssrf_marker_detection=bool(
            getattr(args, "enable_graphql_ssrf_marker_detection", True)
        ),
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
    budget: ExecutionBudget | None = None,
    api_style: ApiStyle = ApiStyle.REST,
) -> tuple[list[RequestRecord], list[ResponseRecord], list[ExecutionResult]]:
    requests: list[RequestRecord] = []
    responses: list[ResponseRecord] = []
    execution_results: list[ExecutionResult] = []
    for payload in payloads:
        if budget is not None:
            decision = budget.allow_request(endpoint.endpoint_id, payload.payload_kind, api_style)
            if not decision.allowed:
                continue
        elif _request_limit_reached(current_request_count + len(requests), max_requests):
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
        if budget is not None:
            budget.record_planned(endpoint.endpoint_id, api_style)
        result = _execute_request(
            executor,
            request_record,
            scan_run_id=scan_run_id,
            timeout_seconds=timeout_seconds,
            auth_material=auth_material,
        )
        execution_results.append(result)
        if budget is not None:
            if result.status == ExecutionStatus.COMPLETED:
                budget.record_executed()
            budget.record_retries(result.retry_count)
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


def _print_progress(args: argparse.Namespace, progress: ProgressTracker) -> None:
    if not bool(getattr(args, "progress", False)) and not bool(getattr(args, "verbose", False)):
        return
    snapshot = progress.snapshot()
    print(
        "YSLFuzz progress: "
        f"phase={snapshot.current_phase}, "
        f"endpoints={snapshot.endpoints_processed}/{snapshot.total_endpoints}, "
        f"payloads={snapshot.total_payloads_generated}, "
        f"planned={snapshot.total_requests_planned}, "
        f"executed={snapshot.requests_executed}, "
        f"skipped={snapshot.requests_skipped}, "
        f"findings={snapshot.findings_so_far}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
