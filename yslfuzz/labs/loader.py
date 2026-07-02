"""Lab manifest loading utilities."""

import json
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from yslfuzz.models.lab import LabManifest


class LabManifestLoadError(ValueError):
    """Raised when a lab manifest cannot be loaded or validated."""


class LabManifestLoader:
    """Load lab pack manifests without executing scans or contacting targets."""

    manifest_name = "lab_manifest.json"

    def load(self, path: str | Path) -> LabManifest:
        """Load one lab manifest and attach resolved local resource paths."""
        source = Path(path)
        if source.is_dir():
            source = source / self.manifest_name
        if not source.is_file():
            raise LabManifestLoadError(f"Lab manifest does not exist: {source}")

        try:
            data = self._load_mapping(source)
            manifest = LabManifest.model_validate(data)
            return self._with_resolved_paths(manifest, source)
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise LabManifestLoadError(f"Invalid lab manifest {source}: {exc}") from exc

    def load_directory(self, path: str | Path) -> list[LabManifest]:
        """Load every lab manifest below a directory in deterministic order."""
        root = Path(path)
        if not root.is_dir():
            raise LabManifestLoadError(f"Lab directory does not exist: {root}")

        manifest_paths: list[Path] = []
        root_manifest = root / self.manifest_name
        if root_manifest.is_file():
            manifest_paths.append(root_manifest)
        manifest_paths.extend(
            sorted(
                candidate
                for candidate in root.rglob(self.manifest_name)
                if candidate != root_manifest
            )
        )
        return [self.load(manifest_path) for manifest_path in manifest_paths]

    def _load_mapping(self, path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("lab manifest root must be an object")
        return cast(dict[str, Any], data)

    def _with_resolved_paths(self, manifest: LabManifest, source: Path) -> LabManifest:
        lab_dir = source.parent.resolve()
        resolved_openapi = self._required_file(lab_dir, manifest.openapi_path, "OpenAPI")
        resolved_ground_truth = self._required_file(
            lab_dir,
            manifest.ground_truth_path,
            "ground truth",
        )
        resolved_benchmark = self._required_file(
            lab_dir,
            manifest.benchmark_config_path,
            "benchmark config",
        )
        return manifest.model_copy(
            update={
                "manifest_path": str(source.resolve()),
                "lab_directory": str(lab_dir),
                "resolved_openapi_path": str(resolved_openapi),
                "resolved_ground_truth_path": str(resolved_ground_truth),
                "resolved_benchmark_config_path": str(resolved_benchmark),
            }
        )

    def _required_file(self, lab_dir: Path, relative_path: str, label: str) -> Path:
        resolved = (lab_dir / relative_path).resolve()
        try:
            resolved.relative_to(lab_dir)
        except ValueError as exc:
            raise LabManifestLoadError(f"{label} path escapes lab directory: {relative_path}") from exc
        if not resolved.is_file():
            raise LabManifestLoadError(f"{label} file does not exist: {resolved}")
        return resolved
