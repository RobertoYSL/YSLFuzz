"""Lab pack metadata models."""

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from pydantic import Field, field_validator, model_validator

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import ApiStyle, PayloadKind


class LabTargetType(StrEnum):
    """Supported lab target types."""

    MOCK = "MOCK"
    LOCAL = "LOCAL"
    EXTERNAL_PLACEHOLDER = "EXTERNAL_PLACEHOLDER"


class LabSetupType(StrEnum):
    """Supported lab setup descriptions."""

    MANUAL = "MANUAL"
    LOCAL_MOCK = "LOCAL_MOCK"
    DOCUMENTATION_ONLY = "DOCUMENTATION_ONLY"


class LabManifest(YSLFuzzModel):
    """Serializable metadata for a reproducible lab pack."""

    lab_id: str
    lab_name: str
    lab_version: str
    description: str
    target_name: str
    target_type: LabTargetType
    api_style: ApiStyle
    openapi_path: str
    ground_truth_path: str
    benchmark_config_path: str
    recommended_base_url: str
    setup_type: LabSetupType
    requires_authentication: bool = False
    required_authentication_types: list[str] = Field(default_factory=list)
    supported_payload_modes: list[PayloadKind] = Field(
        default_factory=lambda: [PayloadKind.VALID]
    )
    expected_vulnerability_count: int = 0
    expected_endpoint_count: int = 0
    safety_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    manifest_path: str | None = None
    lab_directory: str | None = None
    resolved_openapi_path: str | None = None
    resolved_ground_truth_path: str | None = None
    resolved_benchmark_config_path: str | None = None

    @field_validator("lab_id", "lab_name", "lab_version", "description", "target_name")
    @classmethod
    def require_non_empty_string(cls, value: str) -> str:
        """Reject empty required string fields."""
        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @field_validator("openapi_path", "ground_truth_path", "benchmark_config_path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        """Require manifest resource paths to be relative and local."""
        path_value = value.strip()
        if not path_value:
            raise ValueError("path must not be empty")
        if "://" in path_value:
            raise ValueError("path must be a local relative path")
        normalized = path_value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("path must be a safe relative path")
        return normalized

    @model_validator(mode="after")
    def validate_lab_manifest(self) -> "LabManifest":
        """Validate enum combinations and count fields."""
        if self.api_style == ApiStyle.UNKNOWN:
            raise ValueError("api_style must not be UNKNOWN")
        if self.expected_vulnerability_count < 0:
            raise ValueError("expected_vulnerability_count must be non-negative")
        if self.expected_endpoint_count < 0:
            raise ValueError("expected_endpoint_count must be non-negative")
        if not self.supported_payload_modes:
            raise ValueError("supported_payload_modes must not be empty")
        if any(not auth_type.strip() for auth_type in self.required_authentication_types):
            raise ValueError("required_authentication_types must not contain empty values")
        return self

    def catalog_summary(self) -> dict[str, Any]:
        """Return stable fields useful for CLI and catalog display."""
        return {
            "lab_id": self.lab_id,
            "lab_name": self.lab_name,
            "lab_version": self.lab_version,
            "api_style": self.api_style.value,
            "requires_authentication": self.requires_authentication,
            "required_authentication_types": list(self.required_authentication_types),
            "tags": list(self.tags),
            "manifest_path": self.manifest_path,
            "openapi_path": self.resolved_openapi_path or self.openapi_path,
            "ground_truth_path": self.resolved_ground_truth_path or self.ground_truth_path,
            "benchmark_config_path": (
                self.resolved_benchmark_config_path or self.benchmark_config_path
            ),
        }
