"""Configuration for conservative GraphQL response analysis."""

from pydantic import field_validator

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import FindingConfidence


class GraphQLAnalysisConfig(YSLFuzzModel):
    """Safe, bounded options for GraphQL-specific detectors."""

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
    minimum_confidence: FindingConfidence | None = None
    include_info_findings: bool = True
    max_error_messages_to_analyze: int = 10
    max_evidence_preview_chars: int = 300
    deterministic: bool = True

    @field_validator("max_error_messages_to_analyze", "max_evidence_preview_chars")
    @classmethod
    def validate_positive_limit(cls, value: int) -> int:
        """Require bounded positive analysis limits."""
        if value <= 0:
            raise ValueError("GraphQL analysis limits must be greater than 0")
        return value

    @classmethod
    def from_object(cls, value: object | None) -> "GraphQLAnalysisConfig":
        """Build GraphQL config from a generic AnalysisConfig-like object."""
        if isinstance(value, cls):
            return value
        data = {}
        for field_name in cls.model_fields:
            if value is not None and hasattr(value, field_name):
                data[field_name] = getattr(value, field_name)
        return cls(**data)

    def summary(self) -> dict[str, object]:
        """Return non-sensitive configuration summary for reports."""
        return {
            "enable_graphql_error_disclosure": self.enable_graphql_error_disclosure,
            "enable_graphql_validation_bypass": self.enable_graphql_validation_bypass,
            "enable_graphql_introspection_exposure": (
                self.enable_graphql_introspection_exposure
            ),
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
            "minimum_confidence": (
                self.minimum_confidence.value if self.minimum_confidence is not None else None
            ),
            "include_info_findings": self.include_info_findings,
            "max_error_messages_to_analyze": self.max_error_messages_to_analyze,
            "max_evidence_preview_chars": self.max_evidence_preview_chars,
            "deterministic": self.deterministic,
        }
