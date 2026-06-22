"""Project, target, scope, and scan configuration models."""

from datetime import datetime
from urllib.parse import urlparse

from pydantic import Field, field_validator

from yslfuzz.models.auth import AuthProfile
from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import ApiStyle, AttackCategory, HttpMethod, PayloadKind, Protocol
from yslfuzz.models.schema import SchemaSource


class ScopeDefinition(YSLFuzzModel):
    allowed_hosts: list[str]
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    blocked_paths: list[str] = Field(default_factory=list)
    max_requests: int | None = None
    max_duration_seconds: int | None = None
    rate_limit_per_second: int | None = 5
    allow_destructive_methods: bool = False
    allowed_methods: list[HttpMethod] = Field(
        default_factory=lambda: [HttpMethod.GET, HttpMethod.POST, HttpMethod.HEAD, HttpMethod.OPTIONS]
    )


class ScanConfiguration(YSLFuzzModel):
    scan_config_id: str = Field(default_factory=lambda: prefixed_id("scan_config"))
    target_id: str
    enabled_attack_categories: list[AttackCategory] = Field(default_factory=list)
    enabled_payload_kinds: list[PayloadKind] = Field(default_factory=lambda: [PayloadKind.VALID])
    max_depth: int = 3
    max_concurrency: int = 10
    request_timeout_seconds: float = 10.0
    follow_redirects: bool = False
    verify_tls: bool = True
    random_seed: int = 0
    store_raw_responses: bool = False
    redact_sensitive_data: bool = True


class Target(YSLFuzzModel):
    target_id: str = Field(default_factory=lambda: prefixed_id("target"))
    name: str
    base_url: str
    api_style: ApiStyle
    protocol: Protocol
    scope: ScopeDefinition
    auth_profile: AuthProfile | None = None
    schema_sources: list[SchemaSource] = Field(default_factory=list)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed_url = urlparse(value)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError("base_url must be a valid HTTP or HTTPS URL")
        return value


class Project(YSLFuzzModel):
    project_id: str = Field(default_factory=lambda: prefixed_id("project"))
    name: str
    description: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    targets: list[Target] = Field(default_factory=list)
    scans: list["ScanRun"] = Field(default_factory=list)


from yslfuzz.models.execution import ScanRun  # noqa: E402

Project.model_rebuild()
