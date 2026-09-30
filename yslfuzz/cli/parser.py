"""Argument parser definition for YSLFuzz."""

from __future__ import annotations

import argparse

from yslfuzz import __version__
from yslfuzz.cli.commands.benchmark import run_benchmark_command
from yslfuzz.cli.commands.evaluate import run_evaluate_command
from yslfuzz.cli.commands.labs import run_labs_command
from yslfuzz.cli.commands.scan import run_scan_command



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
        help="Run a REST/OpenAPI or GraphQL scan",
        description="Run a REST/OpenAPI or GraphQL scan",
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
    # Dynamic auth flags
    scan_parser.add_argument(
        "--auth-login-url",
        default=None,
        help="Pre-flight login endpoint URL or path for dynamic auth",
    )
    scan_parser.add_argument(
        "--auth-login-payload",
        default=None,
        help="JSON payload for pre-flight login",
    )
    scan_parser.add_argument(
        "--auth-login-user-env",
        default=None,
        help="Environment variable name containing login username/email",
    )
    scan_parser.add_argument(
        "--auth-login-pass-env",
        default=None,
        help="Environment variable name containing login password",
    )
    scan_parser.add_argument(
        "--auth-token-field",
        default="token",
        help="JSON response field to extract auth token (default: token)",
    )
    scan_parser.add_argument(
        "--auth-token-type",
        default="Bearer",
        help="Token type prefix (default: Bearer)",
    )
    # Stateful workflows flag
    scan_parser.add_argument(
        "--stateful",
        "--enable-workflows",
        dest="stateful",
        action="store_true",
        help="Enable stateful workflow execution derived from dependency graph",
    )
    # Multi-User / BOLA flags
    scan_parser.add_argument(
        "--auth-user2-bearer-env",
        default=None,
        help="Secondary user bearer token ENV_VAR for BOLA differential testing",
    )
    scan_parser.add_argument(
        "--enable-bola-check",
        action="store_true",
        help="Enable BOLA/IDOR multi-user differential testing",
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
