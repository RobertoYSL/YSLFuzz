"""Scan stability, budget, retry and progress models."""

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from yslfuzz.models.base import YSLFuzzModel, utc_now


class ScanLimits(YSLFuzzModel):
    """Bounded scan limits applied before execution where possible."""

    max_requests: int | None = None
    max_requests_per_endpoint: int | None = None
    max_payloads_total: int | None = None
    max_payloads_per_endpoint: int | None = None
    max_findings: int | None = None
    max_duration_seconds: float | None = None
    max_graphql_operations: int | None = None
    max_graphql_requests: int | None = None
    max_rest_requests: int | None = None

    @field_validator(
        "max_requests",
        "max_requests_per_endpoint",
        "max_payloads_total",
        "max_payloads_per_endpoint",
        "max_findings",
        "max_graphql_operations",
        "max_graphql_requests",
        "max_rest_requests",
    )
    @classmethod
    def validate_optional_non_negative_int(cls, value: int | None) -> int | None:
        """Reject negative integer limits."""
        if value is not None and value < 0:
            raise ValueError("scan limits must be non-negative")
        return value

    @field_validator("max_duration_seconds")
    @classmethod
    def validate_optional_positive_duration(cls, value: float | None) -> float | None:
        """Reject negative duration limits."""
        if value is not None and value < 0:
            raise ValueError("max_duration_seconds must be non-negative")
        return value


class RateLimitConfig(YSLFuzzModel):
    """Simple deterministic request pacing configuration."""

    requests_per_second: float | None = None
    min_delay_ms: int | None = None
    burst_size: int | None = None

    @model_validator(mode="after")
    def validate_rate_limit(self) -> "RateLimitConfig":
        """Validate non-negative rate limit fields."""
        if self.requests_per_second is not None and self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than 0")
        if self.min_delay_ms is not None and self.min_delay_ms < 0:
            raise ValueError("min_delay_ms must be non-negative")
        if self.burst_size is not None and self.burst_size <= 0:
            raise ValueError("burst_size must be greater than 0")
        return self


class RetryConfig(YSLFuzzModel):
    """Conservative bounded retry configuration."""

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
    def validate_retry(self) -> "RetryConfig":
        """Reject unbounded retry settings."""
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


class ScanTimeoutConfig(YSLFuzzModel):
    """Global scan deadline configuration and state."""

    max_duration_seconds: float | None = None
    started_at: datetime = Field(default_factory=utc_now)
    timed_out: bool = False

    @property
    def deadline_epoch_seconds(self) -> float | None:
        """Return an epoch deadline when max duration is configured."""
        if self.max_duration_seconds is None:
            return None
        return self.started_at.timestamp() + self.max_duration_seconds


class ProgressSnapshot(YSLFuzzModel):
    """Small progress snapshot suitable for CLI/report metadata."""

    total_endpoints: int = 0
    endpoints_processed: int = 0
    total_payloads_generated: int = 0
    total_requests_planned: int = 0
    requests_executed: int = 0
    requests_skipped: int = 0
    findings_so_far: int = 0
    current_phase: str = "initializing"
    started_at: datetime = Field(default_factory=utc_now)
    elapsed_seconds: float = 0.0


class StabilityPolicy(YSLFuzzModel):
    """Combined stability controls for scan execution."""

    limits: ScanLimits = Field(default_factory=ScanLimits)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    progress: bool = False

