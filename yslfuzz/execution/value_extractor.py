"""Runtime value extraction from response records."""

import json
from collections.abc import Mapping
from typing import Any

from yslfuzz.models.base import is_sensitive_key
from yslfuzz.models.dependency import ValueExtractor
from yslfuzz.models.execution import ResponseRecord


class ValueExtractionError(ValueError):
    """Raised when a required value cannot be extracted."""


class ValueExtractionEngine:
    """Extract values from response records using simple safe expressions."""

    def extract(
        self,
        response_record: ResponseRecord,
        extractor: ValueExtractor,
        required: bool = True,
    ) -> dict[str, Any]:
        """Extract a value and return it under target_name plus safe identifier aliases."""
        value = self._extract_value(response_record, extractor)
        if value is None:
            if required:
                raise ValueExtractionError(
                    f"Could not extract required value '{extractor.target_name}' "
                    f"from {extractor.source}:{extractor.expression}"
                )
            return {}
        if is_sensitive_key(extractor.target_name):
            return {}
        return self._value_mapping(extractor.target_name, value)

    def _extract_value(self, response_record: ResponseRecord, extractor: ValueExtractor) -> Any | None:
        source = extractor.source.upper().replace(".", "_").replace("-", "_")
        if source in {"JSON_BODY", "RESPONSE_BODY", "BODY", "RESPONSE_BODY_JSON"}:
            return self._extract_json_body(response_record.body_preview, extractor.expression)
        if source == "HEADER":
            return self._case_insensitive_lookup(response_record.headers, extractor.expression)
        if source == "COOKIE":
            return self._case_insensitive_lookup(response_record.cookies, extractor.expression)
        if source == "STATUS_CODE":
            return response_record.status_code
        return None

    def _extract_json_body(self, body_preview: str | None, expression: str) -> Any | None:
        if body_preview is None or body_preview == "[REDACTED]":
            return None
        try:
            body = json.loads(body_preview)
        except json.JSONDecodeError:
            return None

        parts = self._expression_parts(expression)
        current: Any = body
        for part in parts:
            if not isinstance(current, Mapping) or part not in current:
                return None
            current = current[part]
        return current

    def _expression_parts(self, expression: str) -> list[str]:
        normalized = expression.strip()
        if normalized.startswith("$."):
            normalized = normalized[2:]
        elif normalized == "$":
            return []
        return [part for part in normalized.split(".") if part]

    def _case_insensitive_lookup(self, values: dict[str, Any], key: str) -> Any | None:
        normalized_key = key.removeprefix("$.").lower()
        for candidate_key, value in values.items():
            if candidate_key.lower() == normalized_key:
                return value
        return None

    def _value_mapping(self, target_name: str, value: Any) -> dict[str, Any]:
        mapping = {target_name: value}
        if target_name == "id":
            return mapping
        if target_name.endswith("_id"):
            mapping["id"] = value
        return mapping
