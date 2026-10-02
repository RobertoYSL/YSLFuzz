"""Deterministic detector registry for the analysis engine."""

from collections.abc import Sequence

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.analysis.detectors import (
    BasicAuthorizationBypassDetector,
    BaselineCrashDetector,
    BolaDetector,
    DifferentialResponseDetector,
    ErrorMessageDetector,
    MassAssignmentDetector,
    ReflectionDetector,
    ResponseDetector,
    SchemaConformanceDetector,
    SensitiveDataExposureDetector,
    StatusCodeAnomalyDetector,
    ValidationBypassDetector,
)
from yslfuzz.analysis.graphql.detectors import (
    GraphQLAuthorizationConsistencyDetector,
    GraphQLBooleanSqlInjectionDetector,
    GraphQLErrorDisclosureDetector,
    GraphQLFieldSuggestionDetector,
    GraphQLInjectionMarkerDetector,
    GraphQLIntrospectionExposureDetector,
    GraphQLMassAssignmentDetector,
    GraphQLReflectionDetector,
    GraphQLSSRFMarkerDetector,
    GraphQLValidationBypassDetector,
)


DETECTOR_FLAGS: dict[str, str] = {
    StatusCodeAnomalyDetector.name: "enable_status_code_anomaly",
    ErrorMessageDetector.name: "enable_error_message_detection",
    ReflectionDetector.name: "enable_reflection_detection",
    DifferentialResponseDetector.name: "enable_differential_response_detection",
    SensitiveDataExposureDetector.name: "enable_sensitive_data_exposure_detection",
    ValidationBypassDetector.name: "enable_validation_bypass_detection",
    MassAssignmentDetector.name: "enable_mass_assignment_detection",
    BasicAuthorizationBypassDetector.name: "enable_authz_bypass_detection",
    BaselineCrashDetector.name: "enable_baseline_crash_detection",
    SchemaConformanceDetector.name: "enable_schema_conformance_detection",
    BolaDetector.name: "enable_bola_detection",
    GraphQLErrorDisclosureDetector.name: "enable_graphql_error_disclosure",
    GraphQLValidationBypassDetector.name: "enable_graphql_validation_bypass",
    GraphQLIntrospectionExposureDetector.name: "enable_graphql_introspection_exposure",
    GraphQLReflectionDetector.name: "enable_graphql_reflection_detection",
    GraphQLMassAssignmentDetector.name: "enable_graphql_mass_assignment_detection",
    GraphQLAuthorizationConsistencyDetector.name: "enable_graphql_authorization_consistency",
    GraphQLInjectionMarkerDetector.name: "enable_graphql_injection_marker_detection",
    GraphQLSSRFMarkerDetector.name: "enable_graphql_ssrf_marker_detection",
    GraphQLFieldSuggestionDetector.name: "enable_graphql_field_suggestion_detection",
    GraphQLBooleanSqlInjectionDetector.name: "enable_graphql_boolean_sqli_detection",
}


def default_detectors(config: AnalysisConfig | None = None) -> list[ResponseDetector]:
    """Return default MVP response detectors in deterministic order."""
    analysis_config = config or AnalysisConfig()
    return [
        StatusCodeAnomalyDetector(analysis_config),
        ErrorMessageDetector(analysis_config),
        ReflectionDetector(analysis_config),
        DifferentialResponseDetector(analysis_config),
        SensitiveDataExposureDetector(analysis_config),
        ValidationBypassDetector(analysis_config),
        MassAssignmentDetector(analysis_config),
        BasicAuthorizationBypassDetector(analysis_config),
        BaselineCrashDetector(analysis_config),
        SchemaConformanceDetector(analysis_config),
        BolaDetector(analysis_config),
        GraphQLErrorDisclosureDetector(analysis_config),
        GraphQLValidationBypassDetector(analysis_config),
        GraphQLIntrospectionExposureDetector(analysis_config),
        GraphQLReflectionDetector(analysis_config),
        GraphQLMassAssignmentDetector(analysis_config),
        GraphQLAuthorizationConsistencyDetector(analysis_config),
        GraphQLInjectionMarkerDetector(analysis_config),
        GraphQLSSRFMarkerDetector(analysis_config),
        GraphQLFieldSuggestionDetector(analysis_config),
        GraphQLBooleanSqlInjectionDetector(analysis_config),
    ]


class DetectorRegistry:
    """Resolve enabled detectors from config and stable detector names."""

    def __init__(
        self,
        detectors: Sequence[ResponseDetector] | None = None,
        config: AnalysisConfig | None = None,
    ) -> None:
        self.config = config or AnalysisConfig()
        self._detectors = list(detectors or default_detectors(self.config))

    def detectors(self) -> list[ResponseDetector]:
        """Return enabled detectors in deterministic registry order."""
        enabled_names = set(self.config.enabled_detectors or [])
        disabled_names = set(self.config.disabled_detectors)
        selected: list[ResponseDetector] = []
        for detector in self._detectors:
            names = {detector.name, detector.detector_id}
            if enabled_names and names.isdisjoint(enabled_names):
                continue
            if not names.isdisjoint(disabled_names):
                continue
            flag_name = DETECTOR_FLAGS.get(detector.name)
            if flag_name is not None and not bool(getattr(self.config, flag_name)):
                continue
            selected.append(detector)
        return selected

    def metadata(self) -> list[dict[str, str]]:
        """Return stable detector name, id, and version metadata."""
        return [
            {
                "detector_id": detector.detector_id,
                "name": detector.name,
                "version": detector.version,
            }
            for detector in self.detectors()
        ]
