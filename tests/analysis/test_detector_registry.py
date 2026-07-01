from yslfuzz.analysis import AnalysisConfig, DetectorRegistry, default_detectors


def test_detector_registry_returns_deterministic_detector_order() -> None:
    first = [detector.name for detector in default_detectors()]
    second = [detector.name for detector in default_detectors()]

    assert first == second
    assert first[:3] == [
        "StatusCodeAnomalyDetector",
        "ErrorMessageDetector",
        "ReflectionDetector",
    ]


def test_detector_registry_can_disable_detectors_by_name() -> None:
    registry = DetectorRegistry(
        config=AnalysisConfig(disabled_detectors=["ReflectionDetector"])
    )

    names = [detector.name for detector in registry.detectors()]

    assert "ReflectionDetector" not in names
    assert "StatusCodeAnomalyDetector" in names


def test_detector_registry_exposes_versions() -> None:
    metadata = DetectorRegistry().metadata()

    assert metadata
    assert all(item["name"] for item in metadata)
    assert all(item["version"] == "0.1.0" for item in metadata)
