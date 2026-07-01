"""Evaluation and ground-truth data models."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import (
    ApiStyle,
    AttackCategory,
    FindingSeverity,
    HttpMethod,
    ParameterLocation,
)


class ExpectedVulnerability(YSLFuzzModel):
    """Ground-truth vulnerability entry for a benchmark lab."""

    ground_truth_id: str
    endpoint_path: str
    endpoint_method: HttpMethod
    attack_category: AttackCategory
    vulnerability_type: str
    expected_severity: FindingSeverity
    affected_parameter: str | None = None
    affected_location: ParameterLocation | None = None
    cwe: str | None = None
    owasp_api_category: str | None = None
    description: str
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_endpoint_path(self) -> "ExpectedVulnerability":
        """Require stable REST-like endpoint paths."""
        if not self.endpoint_path.startswith("/"):
            raise ValueError("endpoint_path must start with /")
        return self


class GroundTruthLab(YSLFuzzModel):
    """Ground-truth metadata for a vulnerable lab target."""

    lab_id: str
    lab_name: str
    lab_version: str
    target_name: str
    target_base_url: str
    api_style: ApiStyle
    expected_vulnerabilities: list[ExpectedVulnerability] = Field(default_factory=list)
    expected_endpoints: list[str] = Field(default_factory=list)
    notes: str | None = None


MatchStatus = Literal[
    "true_positive",
    "false_positive",
    "false_negative",
    "unmatched_finding",
    "unmatched_ground_truth",
]


class FindingMatch(YSLFuzzModel):
    """Result of matching one finding or ground-truth item."""

    match_id: str = Field(default_factory=lambda: prefixed_id("match"))
    scan_run_id: str
    match_status: MatchStatus
    finding_id: str | None = None
    ground_truth_id: str | None = None
    endpoint_method: HttpMethod | None = None
    endpoint_path: str | None = None
    attack_category: AttackCategory | None = None
    expected_severity: FindingSeverity | None = None
    finding_severity: FindingSeverity | None = None
    affected_parameter: str | None = None
    reason: str


class EvaluationMetrics(YSLFuzzModel):
    """Benchmark metrics for comparing a YSLFuzz report with ground truth."""

    scan_run_id: str
    lab_id: str
    total_expected_vulnerabilities: int = 0
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    endpoint_coverage: float = 0.0
    payload_validity_rate: float = 0.0
    total_requests: int = 0
    total_payloads_generated: int = 0
    total_payloads_executed: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_attack_category: dict[str, int] = Field(default_factory=dict)
    execution_time_seconds: float | None = None


class EvaluationReport(YSLFuzzModel):
    """Serializable benchmark evaluation result."""

    evaluation_report_id: str = Field(default_factory=lambda: prefixed_id("evaluation_report"))
    scan_run_id: str
    lab: GroundTruthLab
    metrics: EvaluationMetrics
    matches: list[FindingMatch] = Field(default_factory=list)
    reproducibility: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=utc_now)
