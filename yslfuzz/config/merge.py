"""Merge scan configuration profiles with explicit overrides."""

from copy import deepcopy
from typing import Any

from yslfuzz.config.models import ScanConfig


class ConfigMerger:
    """Merge nested override dictionaries into a ScanConfig."""

    def merge(self, config: ScanConfig, cli_overrides: dict[str, Any]) -> ScanConfig:
        """Return a new ScanConfig with overrides applied."""
        data = config.model_dump(mode="json")
        self._deep_update(data, cli_overrides)
        return ScanConfig.model_validate(data)

    def _deep_update(self, target: dict[str, Any], updates: dict[str, Any]) -> None:
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                self._deep_update(target[key], value)
            else:
                target[key] = deepcopy(value)
