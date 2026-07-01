import pytest

from yslfuzz.analysis import AnalysisConfig
from yslfuzz.models import FindingConfidence


def test_analysis_config_safe_defaults() -> None:
    config = AnalysisConfig()

    assert config.enabled_detectors is None
    assert config.disabled_detectors == []
    assert config.minimum_confidence is None
    assert config.include_info_findings is True
    assert config.enable_status_code_anomaly is True
    assert config.enable_validation_bypass_detection is True
    assert config.enable_mass_assignment_detection is True
    assert config.enable_authz_bypass_detection is True
    assert config.response_size_delta_threshold_ratio == 0.5
    assert config.response_time_delta_threshold_ms == 250.0


def test_analysis_config_summary_is_stable_and_non_sensitive() -> None:
    config = AnalysisConfig(
        disabled_detectors=["ReflectionDetector"],
        minimum_confidence=FindingConfidence.MEDIUM,
    )

    summary = config.summary()

    assert summary["disabled_detectors"] == ["ReflectionDetector"]
    assert summary["minimum_confidence"] == "MEDIUM"


def test_analysis_config_rejects_negative_thresholds() -> None:
    with pytest.raises(ValueError):
        AnalysisConfig(response_size_delta_threshold_ratio=-0.1)
