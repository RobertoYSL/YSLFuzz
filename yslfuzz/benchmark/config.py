"""Benchmark configuration loading and hashing."""

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from yslfuzz.models.benchmark import BenchmarkConfig


class BenchmarkConfigError(ValueError):
    """Raised when benchmark configuration cannot be loaded or validated."""


class BenchmarkConfigLoader:
    """Load benchmark JSON/YAML configuration files."""

    def load(self, path: str | Path) -> BenchmarkConfig:
        """Load a benchmark configuration file."""
        source = Path(path)
        if not source.is_file():
            raise BenchmarkConfigError(f"Benchmark config file does not exist: {source}")
        try:
            data = self._load_mapping(source)
            return BenchmarkConfig.model_validate(data)
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise BenchmarkConfigError(f"Invalid benchmark config {source}: {exc}") from exc

    def config_hash(self, config: BenchmarkConfig) -> str:
        """Return a deterministic SHA-256 hash for a benchmark config."""
        encoded = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return sha256(encoded.encode("utf-8")).hexdigest()

    def _load_mapping(self, path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("benchmark config root must be an object")
        return cast(dict[str, Any], data)
