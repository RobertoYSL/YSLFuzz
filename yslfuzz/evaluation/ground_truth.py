"""Ground-truth lab metadata loading."""

import json
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from yslfuzz.models.evaluation import GroundTruthLab


class GroundTruthLoadError(ValueError):
    """Raised when a ground-truth file cannot be loaded or validated."""


class GroundTruthLoader:
    """Load JSON or YAML ground-truth files into validated models."""

    def load(self, path: str | Path) -> GroundTruthLab:
        """Load and validate a ground-truth lab definition."""
        source = Path(path)
        if not source.is_file():
            raise GroundTruthLoadError(f"Ground-truth file does not exist: {source}")
        try:
            data = self._load_mapping(source)
            return GroundTruthLab.model_validate(data)
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise GroundTruthLoadError(f"Invalid ground-truth file {source}: {exc}") from exc

    def _load_mapping(self, path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("ground-truth root must be an object")
        return cast(dict[str, Any], data)
