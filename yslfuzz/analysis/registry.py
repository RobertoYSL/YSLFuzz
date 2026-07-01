"""Deterministic detector registry for the analysis engine."""

from collections.abc import Sequence

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.analysis.detectors import (
    BasicAuthorizationBypassDetector,
    DifferentialResponseDetector,
    ErrorMessageDetector,
    MassAssignmentDetector,
    ReflectionDetector,
    ResponseDetector,
    SensitiveDataExposureDetector,
    StatusCodeAnomalyDetector,
    ValidationBypassDetector,
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
