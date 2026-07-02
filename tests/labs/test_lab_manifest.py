import pytest
from pydantic import ValidationError

from yslfuzz.models import ApiStyle, PayloadKind
from yslfuzz.models.lab import LabManifest, LabSetupType, LabTargetType


def test_lab_manifest_validates_required_fields() -> None:
    manifest = _manifest()

    assert manifest.lab_id == "lab-1"
    assert manifest.target_type == LabTargetType.MOCK


def test_lab_manifest_rejects_missing_required_fields() -> None:
    data = _manifest().model_dump(mode="json")
    data.pop("lab_id")

    with pytest.raises(ValidationError):
        LabManifest.model_validate(data)


def test_lab_manifest_rejects_invalid_api_style() -> None:
    data = _manifest().model_dump(mode="json")
    data["api_style"] = "SOAP"

    with pytest.raises(ValidationError):
        LabManifest.model_validate(data)


def test_lab_manifest_rejects_invalid_setup_type() -> None:
    data = _manifest().model_dump(mode="json")
    data["setup_type"] = "AUTO_DOWNLOAD"

    with pytest.raises(ValidationError):
        LabManifest.model_validate(data)


def test_lab_manifest_supports_safe_defaults() -> None:
    manifest = LabManifest(
        lab_id="lab-1",
        lab_name="Lab 1",
        lab_version="0.1.0",
        description="Local test lab.",
        target_name="target",
        target_type=LabTargetType.MOCK,
        api_style=ApiStyle.REST,
        openapi_path="openapi.yaml",
        ground_truth_path="ground_truth.json",
        benchmark_config_path="benchmark.json",
        recommended_base_url="http://localhost:8000",
        setup_type=LabSetupType.MANUAL,
    )

    assert manifest.requires_authentication is False
    assert manifest.supported_payload_modes == [PayloadKind.VALID]
    assert manifest.safety_notes == []
    assert manifest.limitations == []


def test_lab_manifest_supports_documented_auth_metadata() -> None:
    manifest = _manifest()
    manifest.requires_authentication = True
    manifest.required_authentication_types = ["bearer"]

    summary = manifest.catalog_summary()

    assert summary["requires_authentication"] is True
    assert summary["required_authentication_types"] == ["bearer"]
    assert "token" not in str(summary).lower()


def test_lab_manifest_rejects_unsafe_paths() -> None:
    data = _manifest().model_dump(mode="json")
    data["openapi_path"] = "../openapi.yaml"

    with pytest.raises(ValidationError):
        LabManifest.model_validate(data)


def _manifest() -> LabManifest:
    return LabManifest(
        lab_id="lab-1",
        lab_name="Lab 1",
        lab_version="0.1.0",
        description="Local test lab.",
        target_name="target",
        target_type=LabTargetType.MOCK,
        api_style=ApiStyle.REST,
        openapi_path="openapi.yaml",
        ground_truth_path="ground_truth.json",
        benchmark_config_path="benchmark.json",
        recommended_base_url="http://localhost:8000",
        setup_type=LabSetupType.MANUAL,
        supported_payload_modes=[PayloadKind.VALID, PayloadKind.ATTACK],
    )
