"""Load JSON/YAML scan configuration profiles."""

import json
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from yslfuzz.config.models import ScanConfig
from yslfuzz.models.base import utc_now


class ConfigLoadError(ValueError):
    """Raised when a scan configuration profile cannot be loaded."""


class ScanConfigLoader:
    """Load and path-resolve scan configuration profiles."""

    def load(self, path: str | Path) -> ScanConfig:
        """Load a JSON or YAML scan configuration profile."""
        source = Path(path)
        if not source.is_file():
            raise ConfigLoadError(f"Scan config file does not exist: {source}")
        try:
            data = self._load_mapping(source)
            config = ScanConfig.model_validate(data)
            return self._resolve_paths(config, source)
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise ConfigLoadError(f"Invalid scan config {source}: {exc}") from exc

    def _load_mapping(self, path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("scan config root must be an object")
        return cast(dict[str, Any], data)

    def _resolve_paths(self, config: ScanConfig, source: Path) -> ScanConfig:
        base_dir = source.resolve().parent
        openapi_path = self._resolve_path(config.target.openapi_path, base_dir)
        if not openapi_path.is_file():
            raise ConfigLoadError(f"Configured OpenAPI file does not exist: {openapi_path}")
        output_path = self._resolve_path(config.reporting.output, base_dir)

        config.target.openapi_path = str(openapi_path)
        config.reporting.output = str(output_path)
        config.config_file_path = str(source.resolve())
        config.config_loaded_at = utc_now().isoformat()
        return config

    def _resolve_path(self, value: str, base_dir: Path) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path.resolve()
        return (base_dir / path).resolve()
