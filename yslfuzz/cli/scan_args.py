"""Scan argument resolution, configuration merging, and helper routines."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from yslfuzz.analysis import AnalysisConfig
from yslfuzz.auth import AuthInjector
from yslfuzz.config import (
    ConfigHasher,
    ConfigMerger,
    ConfigValidator,
    ScanConfig,
    ScanConfigLoader,
)
from yslfuzz.execution import (
    BackoffPolicy,
    DestructiveMethodBlockedError,
    ExecutionBudget,
    HttpExecutor,
    ProgressTracker,
    RateLimiter,
    RequestBuilder,
    RetryPolicy,
    ScopeValidator,
    ScopeViolationError,
)
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
    ScopeDefinition,
    Target,
)
from yslfuzz.models.base import utc_now
from yslfuzz.models.enums import PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Endpoint
from yslfuzz.models.stability import RateLimitConfig, RetryConfig, ScanLimits
from yslfuzz.payloads import (
    AttackGenerationConfig,
    AttackPayloadGenerator,
    MutationConfig,
    MutationEngine,
)



def _provided_options(argv: Sequence[str]) -> set[str]:
    options: set[str] = set()
    for item in argv:
        if item.startswith("--"):
            options.add(item.split("=", 1)[0])
    return options


def _apply_preset(args: argparse.Namespace) -> None:
    """Expand preset profiles into concrete scan options unless explicitly overridden."""
    preset = getattr(args, "preset", None)
    if not preset:
        return
    preset = str(preset).lower()
    provided: set[str] = getattr(args, "_provided_options", set())

    if preset == "quick":
        if "--stateful" not in provided and "--enable-workflows" not in provided:
            args.stateful = False
        if "--include-boundary-payloads" not in provided:
            args.include_boundary_payloads = False
        if "--include-invalid-payloads" not in provided:
            args.include_invalid_payloads = False
        if "--include-mutated-payloads" not in provided:
            args.include_mutated_payloads = False
        if "--include-attack-payloads" not in provided:
            args.include_attack_payloads = False
        if "--execute-mutations" not in provided:
            args.execute_mutations = False
        if "--execute-attacks" not in provided:
            args.execute_attacks = False
        if "--enable-bola-check" not in provided:
            args.enable_bola_check = False

    elif preset == "standard":
        if "--stateful" not in provided and "--enable-workflows" not in provided:
            args.stateful = True
        if "--include-boundary-payloads" not in provided:
            args.include_boundary_payloads = False
        if "--include-invalid-payloads" not in provided:
            args.include_invalid_payloads = False
        if "--include-mutated-payloads" not in provided:
            args.include_mutated_payloads = False
        if "--include-attack-payloads" not in provided:
            args.include_attack_payloads = False
        if "--execute-mutations" not in provided:
            args.execute_mutations = False
        if "--execute-attacks" not in provided:
            args.execute_attacks = False
        if "--enable-bola-check" not in provided:
            args.enable_bola_check = False

    elif preset in ("deep", "full"):
        if "--stateful" not in provided and "--enable-workflows" not in provided:
            args.stateful = True
        if "--include-boundary-payloads" not in provided:
            args.include_boundary_payloads = True
        if "--include-invalid-payloads" not in provided:
            args.include_invalid_payloads = True
        if "--include-mutated-payloads" not in provided:
            args.include_mutated_payloads = True
        if "--include-attack-payloads" not in provided:
            args.include_attack_payloads = True
        if "--execute-mutations" not in provided:
            args.execute_mutations = True
        if "--execute-attacks" not in provided:
            args.execute_attacks = True
        if "--enable-bola-check" not in provided:
            if bool(getattr(args, "auth_user2_bearer_env", None)):
                args.enable_bola_check = True
        if "--max-attack-requests-per-endpoint" not in provided:
            args.max_attack_requests_per_endpoint = 15


def _confirm_dangerous_execution(
    args: argparse.Namespace,
    target_url: str | None = None,
) -> bool:
    """Prompt user for confirmation if active attacks or mutations are requested.

    Returns True if confirmed and authorized to proceed, False if user cancelled.
    Raises ValueError if non-interactive and neither -y/--yes nor legacy authorization was given.
    """
    if bool(getattr(args, "dry_run", False)):
        return True

    attacks_active = bool(getattr(args, "execute_attacks", False))
    mutations_active = bool(getattr(args, "execute_mutations", False))
    if not attacks_active and not mutations_active:
        return True

    # Check if already confirmed via -y / --yes or legacy flags
    confirmed_by_flag = bool(getattr(args, "yes", False))
    has_legacy_attack_auth = bool(getattr(args, "i_understand_this_is_authorized", False))
    has_legacy_mutation_auth = bool(
        getattr(args, "i_understand_mutation_execution_is_authorized", False)
    )

    if attacks_active and mutations_active:
        if confirmed_by_flag or (has_legacy_attack_auth and has_legacy_mutation_auth):
            args.i_understand_this_is_authorized = True
            args.i_understand_mutation_execution_is_authorized = True
            return True
    elif attacks_active:
        if confirmed_by_flag or has_legacy_attack_auth:
            args.i_understand_this_is_authorized = True
            return True
    elif mutations_active:
        if confirmed_by_flag or has_legacy_mutation_auth:
            args.i_understand_mutation_execution_is_authorized = True
            return True

    # If stdin is not interactive (e.g. CI/CD or automated test), we cannot prompt
    if not sys.stdin.isatty():
        raise ValueError(
            "Active attack or mutation execution requires confirmation. "
            "In automated or non-interactive environments, pass '-y' / '--yes' to proceed."
        )

    # Interactive prompt
    print("\n" + "=" * 80)
    print("⚠️   AVVISO DI SICUREZZA - SCANSIONE ATTIVA / MUTAZIONI")
    print("=" * 80)
    if target_url:
        print(f" Target bersaglio: {target_url}")
    print(" Questa modalità invierà traffico di penetrazione e fuzzing che include:")
    if attacks_active:
        print("   • Payload di attacco (SQLi, Command Injection, BOLA differential testing)")
    if mutations_active:
        print("   • Mutazioni estreme (boundary values, payload non validi, type-confusion)")
    print("\n Possibili conseguenze:")
    print("   • Modifiche o cancellazioni di dati nel database di test")
    print("   • Errori 500 / crash o instabilità temporanea del servizio")
    print("   • Allarmi o blocchi di sicurezza nei log di rete")
    print("\n Assicurati di avere l'autorizzazione per eseguire penetration testing su questo target.")
    print("=" * 80)

    try:
        reply = input("Vuoi procedere con la scansione? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nScansione annullata.")
        return False

    if reply in ("y", "yes"):
        print("Conferma ricevuta. Avvio della scansione...\n")
        args.i_understand_this_is_authorized = True
        args.i_understand_mutation_execution_is_authorized = True
        return True

    print("Scansione annullata dall'utente.")
    return False


def _effective_scan_args(args: argparse.Namespace) -> argparse.Namespace:
    _apply_preset(args)
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
    effective = _args_from_scan_config(args, merged_config, config_hash)
    _apply_preset(effective)
    return effective


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
    effective.enable_graphql_field_suggestion_detection = (
        config.analysis.enable_graphql_field_suggestion_detection
    )
    effective.enable_graphql_boolean_sqli_detection = (
        config.analysis.enable_graphql_boolean_sqli_detection
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
    cli_main = sys.modules.get("yslfuzz.cli.main")
    executor_cls = getattr(cli_main, "HttpExecutor", HttpExecutor) if cli_main else HttpExecutor
    try:
        return executor_cls(
            rate_limiter=rate_limiter,
            retry_policy=RetryPolicy(retry_config),
            backoff_policy=BackoffPolicy(retry_config),
        )
    except TypeError:
        return executor_cls()



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


def _effective_graphql_request_limit(
    graphql_max_requests: int | None,
    max_requests: int | None,
) -> int | None:
    limits = [limit for limit in (graphql_max_requests, max_requests) if limit is not None]
    if not limits:
        return None
    return min(limits)


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
        enable_graphql_field_suggestion_detection=bool(
            getattr(args, "enable_graphql_field_suggestion_detection", True)
        ),
        enable_graphql_boolean_sqli_detection=bool(
            getattr(args, "enable_graphql_boolean_sqli_detection", True)
        ),
    )



def _auth_profile_from_args(args: argparse.Namespace) -> AuthProfile | None:
    bearer_env = getattr(args, "auth_bearer_env", None)
    api_key_env = getattr(args, "auth_api_key_env", None)
    api_key_header = getattr(args, "auth_api_key_header", "X-API-Key")
    cookie_env = getattr(args, "auth_cookie_env", None)
    cookie_name = getattr(args, "auth_cookie_name", "session")
    custom_headers = list(getattr(args, "auth_header", []) or [])
    login_url = getattr(args, "auth_login_url", None)
    login_payload = getattr(args, "auth_login_payload", None)
    login_user_env = getattr(args, "auth_login_user_env", None)
    login_pass_env = getattr(args, "auth_login_pass_env", None)
    token_field = getattr(args, "auth_token_field", "token")
    token_type = getattr(args, "auth_token_type", "Bearer")

    configured_modes = sum(
        bool(value)
        for value in (
            bearer_env,
            api_key_env,
            cookie_env,
            custom_headers,
            login_url,
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
    if login_url:
        body = {}
        if login_payload:
            try:
                body = json.loads(login_payload)
            except Exception:
                body = {"payload": login_payload}
        return AuthProfile(
            name="cli-login",
            auth_type=AuthType.BEARER,
            login_url=login_url,
            login_body=body,
            login_user_env=login_user_env,
            login_pass_env=login_pass_env,
            token_field=token_field,
            token_type=token_type,
        )

    refs = [
        AuthCredentialRef(env_var=env_var, header_name=header_name)
        for header_name, env_var in (_parse_auth_header(value) for value in custom_headers)
    ]
    return AuthProfile(name="cli-custom-header", auth_type=AuthType.CUSTOM, credential_refs=refs)


def _auth_user2_profile_from_args(args: argparse.Namespace) -> AuthProfile | None:
    user2_bearer = getattr(args, "auth_user2_bearer_env", None)
    if not user2_bearer:
        return None
    return AuthProfile(
        name="cli-user2-bearer",
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var=user2_bearer),
    )



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
    markdown_path: Path | None = None,
    findings: Sequence[Any] = (),
    endpoints: Sequence[Any] = (),
    workflow_stats: dict[str, Any] | None = None,
    target_url: str | None = None,
    preset: str | None = None,
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

    lines = [
        "",
        "=" * 80,
        "                         YSLFUZZ SCAN SUMMARY                          ",
        "=" * 80,
    ]
    if target_url:
        lines.append(f" Target:            {target_url}")
    lines.append(f" Mode:              {mode}" + (f" (preset: {preset})" if preset else ""))
    lines.append(f" Endpoints:         {total_endpoints}")
    lines.append(
        f" Requests:          {total_requests} (successful: {successful_requests}, failed: {failed_requests})"
    )
    lines.append(
        f" Payloads:          {payloads_generated} "
        f"(valid: {valid_payloads_generated}, boundary: {boundary_payloads_generated}, "
        f"invalid: {invalid_payloads_generated}, mutated: {mutated_payloads_generated}, "
        f"attack: {attack_payloads_generated})"
    )
    if workflow_stats:
        lines.append(
            f" Workflows:         {workflow_stats.get('workflows_executed', 0)}/{workflow_stats.get('workflows_detected', 0)} executed "
            f"({workflow_stats.get('known_values_extracted', 0)} dynamic parameters propagated)"
        )

    lines.append("-" * 80)
    lines.append(f" Findings Total:    {findings_total}")

    if findings_total > 0 and findings:
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = getattr(f, "severity", None)
            sev_str = (sev.value if hasattr(sev, "value") else str(sev)) if sev is not None else "UNKNOWN"
            sev_counts[sev_str] = sev_counts.get(sev_str, 0) + 1

        for sev_name, icon in (
            ("CRITICAL", "🔴"),
            ("HIGH", "🔴"),
            ("MEDIUM", "🟡"),
            ("LOW", "🔵"),
            ("INFO", "⚪"),
        ):
            if sev_name in sev_counts:
                lines.append(f"   {icon} {sev_name:<10}: {sev_counts[sev_name]}")

        endpoint_map: dict[str, str] = {}
        for ep in endpoints:
            ep_id = getattr(ep, "endpoint_id", None)
            if ep_id:
                m = getattr(ep, "method", None)
                m_str = (m.value if hasattr(m, "value") else str(m)) if m else ""
                p_str = getattr(ep, "path", "")
                op_type = getattr(ep, "graphql_operation_type", None)
                op_name = getattr(ep, "graphql_operation_name", None)
                if op_type and op_name:
                    endpoint_map[ep_id] = f"{m_str} {p_str} ({op_type}: {op_name})".strip()
                else:
                    endpoint_map[ep_id] = f"{m_str} {p_str}".strip()

        ep_findings: dict[str, list[Any]] = {}
        for f in findings:
            ep_id_raw = getattr(f, "endpoint_id", None)
            ep_id_str: str = str(ep_id_raw) if ep_id_raw is not None else "unknown"
            ep_findings.setdefault(ep_id_str, []).append(f)

        if ep_findings:
            lines.append("")
            lines.append(" Top Vulnerable Endpoints:")
            sorted_eps = sorted(ep_findings.items(), key=lambda kv: len(kv[1]), reverse=True)
            for ep_id, f_list in sorted_eps[:5]:
                ep_desc = endpoint_map.get(ep_id, ep_id)
                sevs = sorted({
                    (
                        getattr(f, "severity").value
                        if hasattr(getattr(f, "severity"), "value")
                        else str(getattr(f, "severity"))
                    )
                    for f in f_list
                    if hasattr(f, "severity")
                })
                lines.append(f"   • {ep_desc:<45} [{', '.join(sevs)}] ({len(f_list)} findings)")

    lines.append("-" * 80)
    lines.append(f" JSON Report:       {output_path}")
    if markdown_path:
        lines.append(f" Markdown Report:   {markdown_path}")
    lines.append("=" * 80)

    print("\n".join(lines))


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
