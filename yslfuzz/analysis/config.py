"""Configuration for deterministic conservative response analysis."""

from pydantic import Field, field_validator

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import FindingConfidence


class AnalysisConfig(YSLFuzzModel):
    """Small configuration object for the Analysis Engine MVP."""

    enabled_detectors: list[str] | None = None
    disabled_detectors: list[str] = Field(default_factory=list)
    minimum_confidence: FindingConfidence | None = None
    include_info_findings: bool = True
    enable_status_code_anomaly: bool = True
    enable_error_message_detection: bool = True
    enable_reflection_detection: bool = True
    enable_differential_response_detection: bool = True
    enable_sensitive_data_exposure_detection: bool = True
    enable_validation_bypass_detection: bool = True
    enable_mass_assignment_detection: bool = True
    enable_authz_bypass_detection: bool = True
    enable_baseline_crash_detection: bool = True
    enable_schema_conformance_detection: bool = True
    enable_bola_detection: bool = True
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
    max_error_messages_to_analyze: int = 10
    max_evidence_preview_chars: int = 300
    response_size_delta_threshold_ratio: float = 0.5
    response_time_delta_threshold_ms: float = 250.0

    @field_validator("disabled_detectors", "enabled_detectors")
    @classmethod
    def normalize_detector_names(cls, value: list[str] | None) -> list[str] | None:
        """Drop empty detector names while preserving caller order."""
        if value is None:
            return None
        return [item.strip() for item in value if item.strip()]

    @field_validator("response_size_delta_threshold_ratio")
    @classmethod
    def validate_size_threshold(cls, value: float) -> float:
        """Require a non-negative response size delta ratio."""
        if value < 0:
            raise ValueError("response_size_delta_threshold_ratio must be non-negative")
        return value

    @field_validator("response_time_delta_threshold_ms")
    @classmethod
    def validate_time_threshold(cls, value: float) -> float:
        """Require a non-negative response time delta threshold."""
        if value < 0:
            raise ValueError("response_time_delta_threshold_ms must be non-negative")
        return value

    @field_validator("max_error_messages_to_analyze", "max_evidence_preview_chars")
    @classmethod
    def validate_graphql_analysis_limits(cls, value: int) -> int:
        """Require bounded positive GraphQL analysis limits."""
        if value <= 0:
            raise ValueError("GraphQL analysis limits must be greater than 0")
        return value

    def summary(self) -> dict[str, object]:
        """Return a stable non-sensitive configuration summary for reports."""
        return {
            "enabled_detectors": self.enabled_detectors,
            "disabled_detectors": sorted(self.disabled_detectors),
            "minimum_confidence": self.minimum_confidence.value
            if self.minimum_confidence is not None
            else None,
            "include_info_findings": self.include_info_findings,
            "enable_status_code_anomaly": self.enable_status_code_anomaly,
            "enable_error_message_detection": self.enable_error_message_detection,
            "enable_reflection_detection": self.enable_reflection_detection,
            "enable_differential_response_detection": self.enable_differential_response_detection,
            "enable_sensitive_data_exposure_detection": (
                self.enable_sensitive_data_exposure_detection
            ),
            "enable_validation_bypass_detection": self.enable_validation_bypass_detection,
            "enable_mass_assignment_detection": self.enable_mass_assignment_detection,
            "enable_authz_bypass_detection": self.enable_authz_bypass_detection,
            "enable_baseline_crash_detection": self.enable_baseline_crash_detection,
            "enable_schema_conformance_detection": self.enable_schema_conformance_detection,
            "enable_bola_detection": self.enable_bola_detection,
            "enable_graphql_error_disclosure": self.enable_graphql_error_disclosure,
            "enable_graphql_validation_bypass": self.enable_graphql_validation_bypass,
            "enable_graphql_introspection_exposure": self.enable_graphql_introspection_exposure,
            "enable_graphql_reflection_detection": self.enable_graphql_reflection_detection,
            "enable_graphql_mass_assignment_detection": (
                self.enable_graphql_mass_assignment_detection
            ),
            "enable_graphql_authorization_consistency": (
                self.enable_graphql_authorization_consistency
            ),
            "enable_graphql_injection_marker_detection": (
                self.enable_graphql_injection_marker_detection
            ),
            "enable_graphql_ssrf_marker_detection": self.enable_graphql_ssrf_marker_detection,
            "enable_graphql_field_suggestion_detection": (
                self.enable_graphql_field_suggestion_detection
            ),
            "enable_graphql_boolean_sqli_detection": (
                self.enable_graphql_boolean_sqli_detection
            ),
            "max_error_messages_to_analyze": self.max_error_messages_to_analyze,
            "max_evidence_preview_chars": self.max_evidence_preview_chars,
            "response_size_delta_threshold_ratio": self.response_size_delta_threshold_ratio,
            "response_time_delta_threshold_ms": self.response_time_delta_threshold_ms,
        }
