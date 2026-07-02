"""Lab pack consistency validation."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from yslfuzz.benchmark import BenchmarkConfigLoader
from yslfuzz.discovery import OpenAPIParseError, OpenAPIParser
from yslfuzz.models.enums import AttackCategory, FindingSeverity, HttpMethod, ParameterLocation
from yslfuzz.models.evaluation import GroundTruthLab
from yslfuzz.models.lab import LabManifest


@dataclass(frozen=True)
class ValidationIssue:
    """One lab pack validation issue."""

    code: str
    message: str
    location: str
    severity: str = "error"


class LabPackValidator:
    """Validate consistency across a lab manifest, OpenAPI file, and ground truth."""

    def validate(self, manifest: LabManifest) -> list[ValidationIssue]:
        """Return validation issues for a loaded lab manifest."""
        issues: list[ValidationIssue] = []
        openapi_path = self._resolved_path(manifest, "openapi")
        ground_truth_path = self._resolved_path(manifest, "ground_truth")
        benchmark_path = self._resolved_path(manifest, "benchmark")

        openapi_endpoints = self._load_openapi_endpoints(openapi_path, issues)
        if openapi_endpoints and len(openapi_endpoints) != manifest.expected_endpoint_count:
            issues.append(
                ValidationIssue(
                    code="expected_endpoint_count_mismatch",
                    message="Manifest expected_endpoint_count does not match OpenAPI endpoints",
                    location="lab_manifest.expected_endpoint_count",
                )
            )
        ground_truth_raw = self._load_mapping(ground_truth_path, "ground_truth", issues)
        if ground_truth_raw is not None:
            self._validate_ground_truth_raw(ground_truth_raw, openapi_endpoints, issues)
            self._validate_ground_truth_model(ground_truth_raw, manifest, issues)
        self._validate_benchmark_config(benchmark_path, issues)
        return issues

    def _resolved_path(self, manifest: LabManifest, kind: str) -> Path:
        if kind == "openapi":
            value = manifest.resolved_openapi_path or manifest.openapi_path
        elif kind == "ground_truth":
            value = manifest.resolved_ground_truth_path or manifest.ground_truth_path
        else:
            value = manifest.resolved_benchmark_config_path or manifest.benchmark_config_path

        path = Path(value)
        if path.is_absolute() or manifest.lab_directory is None:
            return path
        return Path(manifest.lab_directory) / path

    def _load_openapi_endpoints(
        self,
        path: Path,
        issues: list[ValidationIssue],
    ) -> set[tuple[str, str]]:
        try:
            api_schema = OpenAPIParser().parse(path)
        except (OpenAPIParseError, OSError) as exc:
            issues.append(
                ValidationIssue(
                    code="invalid_openapi",
                    message=str(exc),
                    location=str(path),
                )
            )
            return set()
        return {
            (endpoint.method.value, endpoint.path)
            for endpoint in api_schema.endpoints
            if endpoint.method is not None and endpoint.path is not None
        }

    def _load_mapping(
        self,
        path: Path,
        label: str,
        issues: list[ValidationIssue],
    ) -> dict[str, Any] | None:
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
        except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
            issues.append(
                ValidationIssue(
                    code=f"invalid_{label}",
                    message=str(exc),
                    location=str(path),
                )
            )
            return None
        if not isinstance(data, dict):
            issues.append(
                ValidationIssue(
                    code=f"invalid_{label}",
                    message=f"{label} root must be an object",
                    location=str(path),
                )
            )
            return None
        return cast(dict[str, Any], data)

    def _validate_ground_truth_raw(
        self,
        data: dict[str, Any],
        openapi_endpoints: set[tuple[str, str]],
        issues: list[ValidationIssue],
    ) -> None:
        vulnerabilities = data.get("expected_vulnerabilities")
        if not isinstance(vulnerabilities, list):
            issues.append(
                ValidationIssue(
                    code="invalid_expected_vulnerabilities",
                    message="expected_vulnerabilities must be a list",
                    location="ground_truth.expected_vulnerabilities",
                )
            )
            return

        seen_ids: set[str] = set()
        for index, item in enumerate(vulnerabilities):
            location = f"ground_truth.expected_vulnerabilities[{index}]"
            if not isinstance(item, dict):
                issues.append(
                    ValidationIssue(
                        code="invalid_expected_vulnerability",
                        message="expected vulnerability must be an object",
                        location=location,
                    )
                )
                continue
            self._validate_expected_vulnerability_item(
                item,
                location,
                seen_ids,
                openapi_endpoints,
                issues,
            )

    def _validate_expected_vulnerability_item(
        self,
        item: dict[str, Any],
        location: str,
        seen_ids: set[str],
        openapi_endpoints: set[tuple[str, str]],
        issues: list[ValidationIssue],
    ) -> None:
        ground_truth_id = item.get("ground_truth_id")
        if not isinstance(ground_truth_id, str) or not ground_truth_id.strip():
            issues.append(
                ValidationIssue(
                    code="missing_ground_truth_id",
                    message="ground_truth_id must be a non-empty string",
                    location=f"{location}.ground_truth_id",
                )
            )
        elif ground_truth_id in seen_ids:
            issues.append(
                ValidationIssue(
                    code="duplicate_ground_truth_id",
                    message=f"Duplicate ground_truth_id: {ground_truth_id}",
                    location=f"{location}.ground_truth_id",
                )
            )
        else:
            seen_ids.add(ground_truth_id)

        endpoint_path = item.get("endpoint_path")
        if not isinstance(endpoint_path, str) or not endpoint_path.startswith("/"):
            issues.append(
                ValidationIssue(
                    code="invalid_endpoint_path",
                    message="endpoint_path must be present and start with /",
                    location=f"{location}.endpoint_path",
                )
            )

        method = item.get("endpoint_method")
        normalized_method: str | None = None
        if not isinstance(method, str) or method.upper() not in {value.value for value in HttpMethod}:
            issues.append(
                ValidationIssue(
                    code="invalid_endpoint_method",
                    message="endpoint_method must be a supported HTTP method",
                    location=f"{location}.endpoint_method",
                )
            )
        elif method != method.upper():
            issues.append(
                ValidationIssue(
                    code="unnormalized_endpoint_method",
                    message="endpoint_method must be uppercase",
                    location=f"{location}.endpoint_method",
                )
            )
            normalized_method = method.upper()
        else:
            normalized_method = method

        attack_category = item.get("attack_category")
        if attack_category not in {value.value for value in AttackCategory}:
            issues.append(
                ValidationIssue(
                    code="invalid_attack_category",
                    message="attack_category is not supported",
                    location=f"{location}.attack_category",
                )
            )

        expected_severity = item.get("expected_severity")
        if expected_severity not in {value.value for value in FindingSeverity}:
            issues.append(
                ValidationIssue(
                    code="invalid_expected_severity",
                    message="expected_severity is not supported",
                    location=f"{location}.expected_severity",
                )
            )

        affected_parameter = item.get("affected_parameter")
        if affected_parameter is not None and not isinstance(affected_parameter, str):
            issues.append(
                ValidationIssue(
                    code="invalid_affected_parameter",
                    message="affected_parameter must be a string when present",
                    location=f"{location}.affected_parameter",
                )
            )
        affected_location = item.get("affected_location")
        if affected_location is not None and affected_location not in {
            value.value for value in ParameterLocation
        }:
            issues.append(
                ValidationIssue(
                    code="invalid_affected_location",
                    message="affected_location is not supported",
                    location=f"{location}.affected_location",
                )
            )

        if (
            openapi_endpoints
            and normalized_method is not None
            and isinstance(endpoint_path, str)
            and (normalized_method, endpoint_path) not in openapi_endpoints
        ):
            issues.append(
                ValidationIssue(
                    code="unknown_endpoint_reference",
                    message=f"Ground truth references unknown endpoint {normalized_method} {endpoint_path}",
                    location=location,
                )
            )

    def _validate_ground_truth_model(
        self,
        data: dict[str, Any],
        manifest: LabManifest,
        issues: list[ValidationIssue],
    ) -> None:
        try:
            ground_truth = GroundTruthLab.model_validate(data)
        except ValidationError as exc:
            issues.append(
                ValidationIssue(
                    code="invalid_ground_truth_model",
                    message=str(exc),
                    location="ground_truth",
                )
            )
            return

        if len(ground_truth.expected_vulnerabilities) != manifest.expected_vulnerability_count:
            issues.append(
                ValidationIssue(
                    code="expected_vulnerability_count_mismatch",
                    message="Manifest expected_vulnerability_count does not match ground truth",
                    location="lab_manifest.expected_vulnerability_count",
                )
            )

    def _validate_benchmark_config(self, path: Path, issues: list[ValidationIssue]) -> None:
        try:
            BenchmarkConfigLoader().load(path)
        except ValueError as exc:
            issues.append(
                ValidationIssue(
                    code="invalid_benchmark_config",
                    message=str(exc),
                    location=str(path),
                )
            )
