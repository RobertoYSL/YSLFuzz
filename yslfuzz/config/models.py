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

    openapi_path: str
    base_url: str
    api_style: ApiStyle = ApiStyle.REST
    target_id: str | None = None
    target_name: str | None = None

    @model_validator(mode="after")
    def validate_target(self) -> "TargetConfigSection":
        """Keep the configuration MVP focused on REST/OpenAPI."""
        if self.api_style != ApiStyle.REST:
            raise ValueError("configuration profiles MVP supports REST/OpenAPI targets only")
        return self


class AuthConfigSection(ConfigModel):
    """Environment-variable authentication references."""

    bearer_env: str | None = None
    api_key_env: str | None = None
    api_key_header: str = "X-API-Key"
    cookie_env: str | None = None
    cookie_name: str = "session"
    custom_headers: list[str] = Field(default_factory=list)

    @field_validator("bearer_env", "api_key_env", "cookie_env")
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
        return bool(self.bearer_env or self.api_key_env or self.cookie_env or self.custom_headers)


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

    @model_validator(mode="after")
    def validate_limits(self) -> "PayloadsConfigSection":
        """Reject negative payload limits."""
        if self.max_mutations_per_payload < 0:
            raise ValueError("max_mutations_per_payload must be non-negative")
        if self.max_mutations_per_field < 0:
            raise ValueError("max_mutations_per_field must be non-negative")
        if self.max_attack_requests_per_endpoint < 0:
            raise ValueError("max_attack_requests_per_endpoint must be non-negative")
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

    @model_validator(mode="after")
    def validate_budgets(self) -> "LimitsConfigSection":
        """Reject negative budget values."""
        for name in ("request_budget", "endpoint_budget", "payload_budget"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")
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
    execution: ExecutionConfigSection = Field(default_factory=ExecutionConfigSection)
    analysis: AnalysisConfigSection = Field(default_factory=AnalysisConfigSection)
    reporting: ReportingConfigSection = Field(default_factory=ReportingConfigSection)
    limits: LimitsConfigSection = Field(default_factory=LimitsConfigSection)
    safety: SafetyConfigSection = Field(default_factory=SafetyConfigSection)
    metadata: ScanMetadataSection = Field(default_factory=ScanMetadataSection)
    config_file_path: str | None = None
    config_loaded_at: str | None = None

    @model_validator(mode="after")
    def apply_limit_aliases(self) -> "ScanConfig":
        """Map request_budget to max_requests when max_requests is not set."""
        if self.execution.max_requests is None and self.limits.request_budget is not None:
            self.execution.max_requests = self.limits.request_budget
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
        }
