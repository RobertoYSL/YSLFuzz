"""Command-line interface entrypoint for YSLFuzz."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from pydantic import ValidationError

from yslfuzz.auth import AuthResolutionError
from yslfuzz.cli.commands.benchmark import run_benchmark_command
from yslfuzz.cli.commands.evaluate import (
    _evaluation_reproducibility,
    _load_report_dict,
    run_evaluate_command,
)
from yslfuzz.cli.commands.graphql import (
    _align_graphql_payload_endpoint_ids,
    _analyze_graphql_execution,
    _graphql_execution_config_from_args,
    _graphql_execution_summary,
    _graphql_mutation_attack_generation_summary,
    _graphql_mutation_config_from_args,
    _graphql_payload_config_from_args,
    _graphql_payload_generation_summary,
    _graphql_payloads_selected_for_execution,
    _payload_counts_by_kind,
    _run_graphql_discovery_command,
)
from yslfuzz.cli.commands.labs import run_labs_command
from yslfuzz.cli.commands.scan import run_scan_command
from yslfuzz.cli.parser import build_parser
from yslfuzz.cli.scan_args import (
    _analysis_config_from_args,
    _apply_preset,
    _args_from_scan_config,
    _attack_categories_from_args,
    _attack_payloads,
    _auth_override_base,
    _auth_overrides_from_args,
    _auth_profile_from_args,
    _auth_report_metadata,
    _auth_user2_profile_from_args,
    _config_overrides_from_args,
    _config_report_metadata,
    _confirm_dangerous_execution,
    _effective_graphql_request_limit,
    _effective_scan_args,
    _execute_payloads,
    _execute_request,
    _graphql_config_value,
    _http_executor_from_args,
    _mutation_config_from_args,
    _mutation_payloads,
    _parse_auth_header,
    _print_progress,
    _print_summary,
    _provided_options,
    _rate_limit_config_from_args,
    _request_limit_reached,
    _retry_config_from_args,
    _retry_status_codes_from_args,
    _scan_limits_from_args,
    _set_override,
    _stability_report_metadata,
    _target_from_args,
    _verbose,
)
from yslfuzz.config import ConfigLoadError, ConfigValidationError
from yslfuzz.discovery import OpenAPIParseError
from yslfuzz.discovery.graphql import (
    GraphQLIntrospectionParseError,
    GraphQLSDLParseError,
    GraphQLSchemaLoadError,
)
from yslfuzz.execution import AttackExecutor, HttpExecutor, RequestBuildError, ScopeViolationError

__all__ = [
    "main",
    "build_parser",
    "run_scan_command",
    "run_evaluate_command",
    "run_benchmark_command",
    "run_labs_command",
    "_run_graphql_discovery_command",
    "_align_graphql_payload_endpoint_ids",
    "_analyze_graphql_execution",
    "_effective_graphql_request_limit",
    "_graphql_execution_config_from_args",
    "_graphql_execution_summary",
    "_graphql_mutation_attack_generation_summary",
    "_graphql_mutation_config_from_args",
    "_graphql_payload_config_from_args",
    "_graphql_payload_generation_summary",
    "_graphql_payloads_selected_for_execution",
    "_payload_counts_by_kind",
    "_load_report_dict",
    "_evaluation_reproducibility",
    "_provided_options",
    "_effective_scan_args",
    "_config_overrides_from_args",
    "_set_override",
    "_auth_overrides_from_args",
    "_auth_override_base",
    "_args_from_scan_config",
    "_graphql_config_value",
    "_config_report_metadata",
    "_target_from_args",
    "_attack_categories_from_args",
    "_retry_status_codes_from_args",
    "_scan_limits_from_args",
    "_rate_limit_config_from_args",
    "_retry_config_from_args",
    "_http_executor_from_args",
    "_stability_report_metadata",
    "_attack_payloads",
    "_mutation_config_from_args",
    "_analysis_config_from_args",
    "_auth_profile_from_args",
    "_auth_user2_profile_from_args",
    "_parse_auth_header",
    "_auth_report_metadata",
    "_confirm_dangerous_execution",
    "_apply_preset",
    "_execute_request",
    "_mutation_payloads",
    "_execute_payloads",
    "_request_limit_reached",
    "_print_summary",
    "_verbose",
    "_print_progress",
    "HttpExecutor",
    "AttackExecutor",
]


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


if __name__ == "__main__":
    raise SystemExit(main())
