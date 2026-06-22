"""Shared Pydantic base types and redaction helpers."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_KEYWORDS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "jwt",
    "password",
    "secret",
    "set-cookie",
    "token",
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def prefixed_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def is_sensitive_key(key: str) -> bool:
    normalized_key = key.lower().replace("-", "_")
    return any(keyword in normalized_key for keyword in SENSITIVE_KEYWORDS)


def redact_value(value: Any) -> Any:
    if value is None:
        return None
    return REDACTED_VALUE


def redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    return {
        key: redact_value(value) if is_sensitive_key(key) else value
        for key, value in values.items()
    }


class YSLFuzzModel(BaseModel):
    """Base model used by all serializable YSLFuzz data entities."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    metadata: dict[str, Any] = Field(default_factory=dict)
