"""Redaction helpers used before execution data is persisted."""

from collections.abc import Mapping
from typing import Any

from yslfuzz.models.base import REDACTED_VALUE, is_sensitive_key


def redact_mapping_values(values: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with sensitive keys redacted."""
    return {
        key: REDACTED_VALUE if is_sensitive_key(str(key)) else _redact_nested(value)
        for key, value in values.items()
    }


def redact_body_value(value: dict[str, Any] | str | None) -> dict[str, Any] | str | None:
    """Redact sensitive body fields in a request body or response preview input."""
    if isinstance(value, dict):
        return redact_mapping_values(value)
    return value


def _redact_nested(value: Any) -> Any:
    if isinstance(value, Mapping):
        return redact_mapping_values(value)
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    return value
