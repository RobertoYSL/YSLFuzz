"""Pydantic models for scan configuration profiles."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from yslfuzz.models.auth import AuthCredentialRef
from yslfuzz.models.enums import ApiStyle, AttackCategory, FindingConfidence


class OutputFormat(StrEnum):
    """Supported report output formats for scan configuration profiles."""

    JSON = "json"


class ConfigModel(BaseModel):
    """Base model for configuration profile sections."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class TargetConfigSection(ConfigModel):
    """Target and schema input configuration."""

    openapi_path: str | None = None
    graphql_schema_path: str | None = None
    base_url: str
    api_style: ApiStyle = ApiStyle.REST
    target_id: str | None = None
    target_name: str | None = None

    @model_validator(mode="after")
    def validate_target(self) -> "TargetConfigSection":
        """Validate the configured local schema source for the selected API style."""
        if self.api_style == ApiStyle.REST:
            if self.openapi_path is None:
                raise ValueError("REST configuration requires openapi_path")
            if self.graphql_schema_path is not None:
                raise ValueError("REST configuration must not set graphql_schema_path")
            return self
        if self.api_style == ApiStyle.GRAPHQL:
            if self.graphql_schema_path is None:
                raise ValueError("GraphQL configuration requires graphql_schema_path")
            if self.openapi_path is not None:
                raise ValueError("GraphQL configuration must not set openapi_path")
            return self
        raise ValueError("configuration profiles support REST or GraphQL targets")


class AuthConfigSection(ConfigModel):
    """Environment-variable authentication references."""

    bearer_env: str | None = None
    api_key_env: str | None = None
    api_key_header: str = "X-API-Key"
    cookie_env: str | None = None
    cookie_name: str = "session"
    custom_headers: list[str] = Field(default_factory=list)
    login_url: str | None = None
    login_payload: str | None = None
    login_user_env: str | None = None
    login_pass_env: str | None = None
    token_field: str = "token"
    token_type: str = "Bearer"
    user2_bearer_env: str | None = None
    user2_login_url: str | None = None
    user2_login_payload: str | None = None

    @field_validator("bearer_env", "api_key_env", "cookie_env", "login_user_env", "login_pass_env", "user2_bearer_env")
    @classmethod
    def validate_env_name(cls, value: str | None) -> str | None:
        """Validate auth env var references without reading environment values."""
        if value is not None:
            AuthCredentialRef(env_var=value)
        return value

    @field_validator("api_key_header", "cookie_name")
    @classmethod
    def validate_plain_name(cls, value: str) -> str:
        """Validate header and cookie names."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("auth header and cookie names must not be empty")
        if any(character in stripped for character in ("\r", "\n", ":")):
            raise ValueError("auth header and cookie names must be plain names")
        return stripped

    @field_validator("custom_headers")
    @classmethod
    def validate_custom_headers(cls, values: list[str]) -> list[str]:
        """Validate custom header mappings as HEADER_NAME:ENV_VAR references."""
        for value in values:
            if ":" not in value:
                raise ValueError("custom auth headers must use HEADER_NAME:ENV_VAR")
            header_name, env_var = value.split(":", 1)
            if not header_name.strip() or not env_var.strip():
                raise ValueError("custom auth headers require both header name and env var")
            AuthCredentialRef(env_var=env_var.strip(), header_name=header_name.strip())
        return values

    @model_validator(mode="after")
    def validate_single_auth_mode(self) -> "AuthConfigSection":
        """Allow only one authentication mode per scan profile."""
        configured_modes = sum(
            bool(value)
            for value in (
                self.bearer_env,
                self.api_key_env,
                self.cookie_env,
                self.custom_headers,
                self.login_url,
            )
        )
        if configured_modes > 1:
            raise ValueError("configuration profiles support only one auth mode per scan")
        if self.api_key_env is None and self.api_key_header != "X-API-Key":
            raise ValueError("api_key_header requires api_key_env")
        if self.cookie_env is None and self.cookie_name != "session":
            raise ValueError("cookie_name requires cookie_env")
        return self

    def configured(self) -> bool:
        """Return true when any auth mode is configured."""
        return bool(
            self.bearer_env
            or self.api_key_env
            or self.cookie_env
            or self.custom_headers
            or self.login_url
        )


class PayloadsConfigSection(ConfigModel):
    """Payload generation configuration."""

    include_valid_payloads: bool = True
    include_boundary_payloads: bool = False
    include_invalid_payloads: bool = False
    include_mutated_payloads: bool = False
    include_attack_payloads: bool = False
    enabled_attack_categories: list[AttackCategory] = Field(default_factory=list)
    max_mutations_per_payload: int = 50
    max_mutations_per_field: int = 4
    max_attack_requests_per_endpoint: int = 5
    allow_invalid_enum_values: bool = False
    disable_type_confusion: bool = False
    disable_boundary_values: bool = False
    disable_null_mutations: bool = False
    mutate_sensitive_fields: bool = False
    allow_extra_input_fields: bool = True
    allow_missing_required_fields: bool = True
    allow_introspection_probe: bool = False
    allow_error_leakage_probe: bool = True
    allow_reflection_probe: bool = True
    graphql_include_queries: bool = True
    graphql_include_mutations: bool = True
    graphql_include_subscriptions: bool = False
    graphql_max_operations: int | None = None
    graphql_max_selection_depth: int = 2
    graphql_max_fields_per_selection: int = 5

    @model_validator(mode="after")
    def validate_limits(self) -> "PayloadsConfigSection":
        """Reject negative payload limits."""
        if self.max_mutations_per_payload < 0:
            raise ValueError("max_mutations_per_payload must be non-negative")
        if self.max_mutations_per_field < 0:
            raise ValueError("max_mutations_per_field must be non-negative")
        if self.max_attack_requests_per_endpoint < 0:
            raise ValueError("max_attack_requests_per_endpoint must be non-negative")
        if self.graphql_max_operations is not None and self.graphql_max_operations < 0:
            raise ValueError("graphql_max_operations must be non-negative")
        if self.graphql_max_selection_depth < 0:
            raise ValueError("graphql_max_selection_depth must be non-negative")
        if self.graphql_max_fields_per_selection <= 0:
            raise ValueError("graphql_max_fields_per_selection must be greater than 0")
        return self


class GraphQLConfigSection(ConfigModel):
    """GraphQL discovery, payload generation, and execution settings."""

    endpoint_path: str = "/graphql"
    include_queries: bool = True
    include_mutations: bool = True
    include_subscriptions: bool = False
    max_selection_depth: int = 2
    max_fields_per_selection: int = 5
    max_operations: int | None = None
    max_requests: int | None = None
    execute_graphql: bool = True
    enable_analysis: bool = True
    include_introspection_probe: bool = False

    @model_validator(mode="after")
    def validate_graphql_settings(self) -> "GraphQLConfigSection":
        """Validate safe GraphQL settings."""
        if not self.endpoint_path.startswith("/"):
            raise ValueError("graphql endpoint_path must start with '/'")
        if "://" in self.endpoint_path:
            raise ValueError("graphql endpoint_path must be a local path, not a URL")
        if self.max_selection_depth < 0:
            raise ValueError("graphql max_selection_depth must be non-negative")
        if self.max_fields_per_selection <= 0:
            raise ValueError("graphql max_fields_per_selection must be greater than 0")
        if self.max_operations is not None and self.max_operations < 0:
            raise ValueError("graphql max_operations must be non-negative")
        if self.max_requests is not None and self.max_requests < 0:
            raise ValueError("graphql max_requests must be non-negative")
        return self


class ExecutionConfigSection(ConfigModel):
    """HTTP execution and opt-in execution configuration."""

    dry_run: bool = True
    timeout: float = 10.0
    max_requests: int | None = None
    allow_destructive: bool = False
    execute_mutations: bool = False
    execute_attacks: bool = False
    i_understand_mutation_execution_is_authorized: bool = False
    i_understand_attack_execution_is_authorized: bool = False
    stateful: bool = False
    enable_workflows: bool = False
    enable_bola_check: bool = False

    @model_validator(mode="after")
    def validate_execution_limits(self) -> "ExecutionConfigSection":
        """Reject invalid execution limits."""
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if self.max_requests is not None and self.max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        return self


class AnalysisConfigSection(ConfigModel):
    """Analysis engine configuration."""

    disabled_detectors: list[str] = Field(default_factory=list)
    analysis_min_confidence: FindingConfidence | None = None
    enable_graphql_error_disclosure: bool = True
    enable_graphql_validation_bypass: bool = True
    enable_graphql_introspection_exposure: bool = True
    enable_graphql_reflection_detection: bool = True
    enable_graphql_mass_assignment_detection: bool = True
    enable_graphql_authorization_consistency: bool = True
    enable_graphql_injection_marker_detection: bool = True
    enable_graphql_ssrf_marker_detection: bool = True
    enable_graphql_field_suggestion_detection: bool = True
    enable_graphql_boolean_sqli_detection: bool = True


class ReportingConfigSection(ConfigModel):
    """Report output configuration."""

    output: str = "yslfuzz_report.json"
    output_format: OutputFormat = OutputFormat.JSON
    include_reproducibility_metadata: bool = True


class LimitsConfigSection(ConfigModel):
    """Reserved scan budget limits mapped to existing execution limits where possible."""

    request_budget: int | None = None
    endpoint_budget: int | None = None
    payload_budget: int | None = None
    max_requests: int | None = None
    max_requests_per_endpoint: int | None = None
    max_payloads_total: int | None = None
    max_duration_seconds: float | None = None
    max_graphql_requests: int | None = None
    max_rest_requests: int | None = None

    @model_validator(mode="after")
    def validate_budgets(self) -> "LimitsConfigSection":
        """Reject negative budget values."""
        for name in (
            "request_budget",
            "endpoint_budget",
            "payload_budget",
            "max_requests",
            "max_requests_per_endpoint",
            "max_payloads_total",
            "max_graphql_requests",
            "max_rest_requests",
        ):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.max_duration_seconds is not None and self.max_duration_seconds < 0:
            raise ValueError("max_duration_seconds must be non-negative")
        return self


class SafetyConfigSection(ConfigModel):
    """Safety controls that must remain enabled by default."""

    require_authorization_for_attack_execution: bool = True
    require_authorization_for_mutation_execution: bool = True
    redact_secrets: bool = True

    @model_validator(mode="after")
    def validate_safety(self) -> "SafetyConfigSection":
        """Keep secret redaction mandatory in the MVP."""
        if not self.redact_secrets:
            raise ValueError("redact_secrets must remain true")
        return self


class RetryConfigSection(ConfigModel):
    """Retry and backoff configuration for scan stability."""

    enabled: bool = False
    max_retries: int = 0
    retry_on_status_codes: list[int] = Field(default_factory=lambda: [429, 500, 502, 503, 504])
    retry_on_timeout: bool = True
    retry_on_connection_error: bool = True
    backoff_initial_ms: int = 100
    backoff_multiplier: float = 2.0
    backoff_max_ms: int = 2000
    jitter: bool = False
    retry_unsafe_methods: bool = False

    @model_validator(mode="after")
    def validate_retry(self) -> "RetryConfigSection":
        """Reject unsafe retry values."""
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.backoff_initial_ms < 0:
            raise ValueError("backoff_initial_ms must be non-negative")
        if self.backoff_max_ms < 0:
            raise ValueError("backoff_max_ms must be non-negative")
        if self.backoff_multiplier < 1:
            raise ValueError("backoff_multiplier must be greater than or equal to 1")
        for status_code in self.retry_on_status_codes:
            if status_code < 100 or status_code > 599:
                raise ValueError("retry status codes must be valid HTTP status codes")
        return self


class StabilityConfigSection(ConfigModel):
    """Rate limiting, retry and progress configuration."""

    rate_limit_rps: float | None = None
    min_request_delay_ms: int | None = None
    retry: RetryConfigSection = Field(default_factory=RetryConfigSection)
    progress: bool = False

    @model_validator(mode="after")
    def validate_stability(self) -> "StabilityConfigSection":
        """Validate stable scan pacing settings."""
        if self.rate_limit_rps is not None and self.rate_limit_rps <= 0:
            raise ValueError("rate_limit_rps must be greater than 0")
        if self.min_request_delay_ms is not None and self.min_request_delay_ms < 0:
            raise ValueError("min_request_delay_ms must be non-negative")
        return self


class ScanMetadataSection(ConfigModel):
    """User-visible scan profile metadata."""

    scan_name: str | None = None
    notes: str | None = None
    tags: list[str] = Field(default_factory=list)


class ScanConfig(ConfigModel):
    """Validated scan configuration profile."""

    target: TargetConfigSection
    auth: AuthConfigSection = Field(default_factory=AuthConfigSection)
    payloads: PayloadsConfigSection = Field(default_factory=PayloadsConfigSection)
    graphql: GraphQLConfigSection = Field(default_factory=GraphQLConfigSection)
    execution: ExecutionConfigSection = Field(default_factory=ExecutionConfigSection)
    analysis: AnalysisConfigSection = Field(default_factory=AnalysisConfigSection)
    reporting: ReportingConfigSection = Field(default_factory=ReportingConfigSection)
    limits: LimitsConfigSection = Field(default_factory=LimitsConfigSection)
    stability: StabilityConfigSection = Field(default_factory=StabilityConfigSection)
    safety: SafetyConfigSection = Field(default_factory=SafetyConfigSection)
    metadata: ScanMetadataSection = Field(default_factory=ScanMetadataSection)
    config_file_path: str | None = None
    config_loaded_at: str | None = None

    @model_validator(mode="after")
    def apply_limit_aliases(self) -> "ScanConfig":
        """Map request_budget to max_requests when max_requests is not set."""
        if self.execution.max_requests is None and self.limits.request_budget is not None:
            self.execution.max_requests = self.limits.request_budget
        if self.execution.max_requests is None and self.limits.max_requests is not None:
            self.execution.max_requests = self.limits.max_requests
        if self.graphql.max_requests is None and self.limits.max_graphql_requests is not None:
            self.graphql.max_requests = self.limits.max_graphql_requests
        return self

    def safe_enabled_modes_summary(self) -> dict[str, Any]:
        """Return safe report metadata for enabled execution and payload modes."""
        return {
            "dry_run": self.execution.dry_run,
            "allow_destructive": self.execution.allow_destructive,
            "execute_attacks": self.execution.execute_attacks,
            "execute_mutations": self.execution.execute_mutations,
            "include_boundary_payloads": self.payloads.include_boundary_payloads,
            "include_invalid_payloads": self.payloads.include_invalid_payloads,
            "include_mutated_payloads": self.payloads.include_mutated_payloads,
            "include_attack_payloads": self.payloads.include_attack_payloads,
            "allow_extra_input_fields": self.payloads.allow_extra_input_fields,
            "allow_missing_required_fields": self.payloads.allow_missing_required_fields,
            "allow_introspection_probe": self.payloads.allow_introspection_probe,
            "graphql_include_introspection_probe": self.graphql.include_introspection_probe,
            "graphql_enable_analysis": self.graphql.enable_analysis,
            "graphql_include_queries": self.payloads.graphql_include_queries,
            "graphql_include_mutations": self.payloads.graphql_include_mutations,
            "graphql_include_subscriptions": self.payloads.graphql_include_subscriptions,
            "graphql_endpoint_path": self.graphql.endpoint_path,
            "graphql_execute_graphql": self.graphql.execute_graphql,
            "max_requests_per_endpoint": self.limits.max_requests_per_endpoint,
            "max_duration_seconds": self.limits.max_duration_seconds,
            "rate_limit_rps": self.stability.rate_limit_rps,
            "min_request_delay_ms": self.stability.min_request_delay_ms,
            "retry_enabled": self.stability.retry.enabled,
            "max_retries": self.stability.retry.max_retries,
            "progress": self.stability.progress,
        }
