"""Reporting and metrics data models."""

from datetime import datetime

from pydantic import Field, model_validator

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now


class ScanMetrics(YSLFuzzModel):
    metrics_id: str = Field(default_factory=lambda: prefixed_id("metrics"))
    scan_run_id: str
    total_endpoints: int = 0
    tested_endpoints: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_requests: int = 0
    payloads_generated: int = 0
    valid_payloads_generated: int = 0
    boundary_payloads_generated: int = 0
    invalid_payloads_generated: int = 0
    mutated_payloads_generated: int = 0
    attack_payloads_generated: int = 0
    valid_payloads_executed: int = 0
    boundary_payloads_executed: int = 0
    invalid_payloads_executed: int = 0
    mutated_payloads_executed: int = 0
    attack_payloads_executed: int = 0
    skipped_payloads_not_authorized: int = 0
    skipped_payloads_by_kind: dict[str, int] = Field(default_factory=dict)
    findings_total: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    average_response_time_ms: float = 0.0
    endpoint_coverage: float = 0.0
    payload_validity_rate: float = 0.0


class ReportSummary(YSLFuzzModel):
    title: str = "YSLFuzz scan report"
    description: str | None = None


class Report(YSLFuzzModel):
    report_id: str = Field(default_factory=lambda: prefixed_id("report"))
    scan_run_id: str
    format: str = "JSON"
    generated_at: datetime = Field(default_factory=utc_now)
    summary: ReportSummary
    findings: list["SecurityFinding"] = Field(default_factory=list)
    metrics: ScanMetrics
    redaction_enabled: bool = True

    @model_validator(mode="after")
    def validate_report_requirements(self) -> "Report":
        if self.metrics is None:
            raise ValueError("Report requires metrics")
        if self.generated_at is None:
            raise ValueError("Report requires generated_at")
        return self


from yslfuzz.models.analysis import SecurityFinding  # noqa: E402

Report.model_rebuild()
