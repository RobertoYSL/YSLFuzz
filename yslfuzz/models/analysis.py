"""Analysis and finding data models."""

from datetime import datetime

from pydantic import Field, field_serializer, model_validator

from yslfuzz.models.base import REDACTED_VALUE, YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import (
    AttackCategory,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ParameterLocation,
)


class Detector(YSLFuzzModel):
    detector_id: str = Field(default_factory=lambda: prefixed_id("detector"))
    name: str
    attack_category: AttackCategory
    description: str
    enabled: bool = True
    version: str = "0.1.0"


class Evidence(YSLFuzzModel):
    evidence_id: str = Field(default_factory=lambda: prefixed_id("evidence"))
    evidence_type: str
    source: str
    description: str
    request_id: str | None = None
    response_id: str | None = None
    field_name: str | None = None
    observed_value_preview: str | None = None
    redacted: bool = True

    @field_serializer("observed_value_preview")
    def serialize_observed_value_preview(self, value: str | None) -> str | None:
        if self.redacted:
            return REDACTED_VALUE if value is not None else None
        return value


class DetectorResult(YSLFuzzModel):
    detector_result_id: str = Field(default_factory=lambda: prefixed_id("detector_result"))
    detector_id: str
    request_id: str
    response_id: str | None = None
    matched: bool = False
    confidence: FindingConfidence = FindingConfidence.LOW
    severity: FindingSeverity = FindingSeverity.INFO
    evidence: list[Evidence] = Field(default_factory=list)
    reason: str | None = None


class SecurityFinding(YSLFuzzModel):
    finding_id: str = Field(default_factory=lambda: prefixed_id("finding"))
    scan_run_id: str
    endpoint_id: str
    title: str
    description: str
    attack_category: AttackCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus = FindingStatus.OPEN
    affected_parameter: str | None = None
    affected_location: ParameterLocation | None = None
    payload_id: str | None = None
    request_ids: list[str]
    response_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_finding_evidence(self) -> "SecurityFinding":
        if not self.request_ids:
            raise ValueError("SecurityFinding requires at least one request_id")
        if self.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL} and not self.evidence:
            raise ValueError("High severity findings require evidence")
        return self
