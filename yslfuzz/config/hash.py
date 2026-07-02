"""Deterministic hashing for scan configuration profiles."""

import json
from hashlib import sha256
from typing import Any

from yslfuzz.config.models import ScanConfig


class ConfigHasher:
    """Compute reproducible hashes for validated scan configs."""

    def hash(self, config: ScanConfig) -> str:
        """Return a SHA-256 hash of normalized config content."""
        encoded = json.dumps(
            self.normalized(config),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return sha256(encoded.encode("utf-8")).hexdigest()

    def normalized(self, config: ScanConfig) -> dict[str, Any]:
        """Return normalized config data excluding runtime timestamps."""
        return config.model_dump(
            mode="json",
            exclude={"config_file_path", "config_loaded_at"},
        )
