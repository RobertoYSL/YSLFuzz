"""Report redaction helpers."""

from collections.abc import Mapping
from typing import Any

from yslfuzz.models.base import REDACTED_VALUE, SENSITIVE_KEYWORDS, is_sensitive_key


def redact_report_value(value: Any) -> Any:
    """Recursively redact sensitive mapping keys in report data."""
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED_VALUE if is_sensitive_key(str(key)) else redact_report_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_report_value(item) for item in value]
    if isinstance(value, str) and any(keyword in value.lower() for keyword in SENSITIVE_KEYWORDS):
        return REDACTED_VALUE
    return value


def contains_raw_secret(value: Any, raw_secret: str) -> bool:
    """Return true when a raw secret appears in nested report data."""
    if isinstance(value, str):
        return raw_secret in value
    if isinstance(value, Mapping):
        return any(contains_raw_secret(item, raw_secret) for item in value.values())
    if isinstance(value, list):
        return any(contains_raw_secret(item, raw_secret) for item in value)
    return False
