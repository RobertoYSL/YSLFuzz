"""Command-line interface for the YSLFuzz MVP pipeline."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse

from pydantic import ValidationError

from yslfuzz import __version__
from yslfuzz.analysis import AnalysisConfig, AnalysisEngine, FindingBuilder
from yslfuzz.benchmark import BenchmarkConfigLoader, BenchmarkRunner
from yslfuzz.discovery import OpenAPIParseError, OpenAPIParser
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
from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    ExecutionResult,
    FindingConfidence,
    HttpMethod,
    Protocol,
    RequestRecord,
    ResponseRecord,
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
    scan_parser.add_argument("--openapi", required=True, help="Local OpenAPI YAML/JSON file")
    scan_parser.add_argument("--base-url", required=True, help="Target base URL")
    scan_parser.add_argument("--output", required=True, help="JSON report output path")
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the YSLFuzz CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OpenAPIParseError, RequestBuildError, ScopeViolationError, ValidationError, ValueError) as exc:
        parser.exit(1, f"yslfuzz: error: {exc}\n")
    except OSError as exc:
        parser.exit(1, f"yslfuzz: error: {exc}\n")
    return 0


def run_scan_command(args: argparse.Namespace) -> int:
    """Run the scan command and return a process exit code."""
    openapi_path = Path(args.openapi)
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
    target = _target_from_args(args.base_url, args.allow_destructive, args.max_requests)
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

        result = executor.execute(
            request_record,
            scan_run_id=scan.scan_run_id,
            timeout_seconds=args.timeout,
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
                attack_bundle = attack_executor.execute_plan(
                    attack_plan,
                    endpoint=endpoint,
                    target=target,
                    scan_run_id=scan.scan_run_id,
                    timeout_seconds=args.timeout,
                    dry_run=bool(args.dry_run),
                )
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
                scope_validator=scope_validator,
                executor=executor,
                timeout_seconds=args.timeout,
                max_requests=args.max_requests,
                current_request_count=len(requests),
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


def _target_from_args(base_url: str, allow_destructive: bool, max_requests: int | None) -> Target:
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
        api_style=ApiStyle.REST,
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
    scope_validator: ScopeValidator,
    executor: HttpExecutor,
    timeout_seconds: float,
    max_requests: int | None,
    current_request_count: int,
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
        try:
            scope_validator.validate(request_record, target.scope)
        except (DestructiveMethodBlockedError, ScopeViolationError):
            continue
        requests.append(request_record)
        result = executor.execute(
            request_record,
            scan_run_id=scan_run_id,
            timeout_seconds=timeout_seconds,
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
