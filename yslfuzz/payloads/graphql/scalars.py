"""Deterministic GraphQL scalar and enum value generation."""

from typing import Any

from yslfuzz.discovery.graphql.models import (
    GraphQLEnum,
    GraphQLSchema,
    GraphQLTypeKind,
    GraphQLTypeRef,
)


class GraphQLScalarValueGenerator:
    """Generate conservative schema-valid values for GraphQL scalar-like types."""

    _BUILTIN_VALUES: dict[str, Any] = {
        "ID": "yslfuzz-id-001",
        "String": "yslfuzz-string",
        "Int": 1,
        "Float": 1.0,
        "Boolean": True,
    }

    def generate(self, type_ref: GraphQLTypeRef, schema: GraphQLSchema) -> Any:
        """Generate a deterministic value for a scalar, enum, list or non-null reference."""
        unwrapped = self._unwrap_non_null(type_ref)
        if unwrapped.kind == GraphQLTypeKind.LIST and unwrapped.of_type is not None:
            return [self.generate(unwrapped.of_type, schema)]
        named_type = unwrapped.named_type()
        if named_type is None:
            return "yslfuzz-string"
        enum = self._enum(named_type, schema)
        if enum is not None:
            return self.generate_enum(enum)
        if self._looks_like_email(named_type):
            return "yslfuzz@example.invalid"
        return self._BUILTIN_VALUES.get(named_type, "yslfuzz-string")

    def generate_enum(self, enum: GraphQLEnum) -> str:
        """Return the first usable enum value deterministically."""
        values = [
            value
            for value in enum.enum_values
            if not self._enum_value_deprecated(enum, value)
        ]
        if not values:
            values = list(enum.enum_values)
        return values[0] if values else "YSLFUZZ_ENUM_VALUE"

    def literal(self, value: Any, type_ref: GraphQLTypeRef, schema: GraphQLSchema) -> str:
        """Render a generated value as a GraphQL literal."""
        unwrapped = self._unwrap_non_null(type_ref)
        if unwrapped.kind == GraphQLTypeKind.LIST and isinstance(value, list):
            item_type = unwrapped.of_type or unwrapped
            return "[" + ", ".join(self.literal(item, item_type, schema) for item in value) + "]"
        named_type = unwrapped.named_type()
        if named_type is not None and self._enum(named_type, schema) is not None:
            return str(value)
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, dict):
            items = []
            for key, item in value.items():
                items.append(f"{key}: {self._literal_any(item)}")
            return "{" + ", ".join(items) + "}"
        return self._quote(str(value))

    def _literal_any(self, value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, list):
            return "[" + ", ".join(self._literal_any(item) for item in value) + "]"
        if isinstance(value, dict):
            return "{" + ", ".join(f"{key}: {self._literal_any(item)}" for key, item in value.items()) + "}"
        return self._quote(str(value))

    def _quote(self, value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _enum(self, name: str, schema: GraphQLSchema) -> GraphQLEnum | None:
        return next((enum for enum in schema.enums if enum.name == name), None)

    def _unwrap_non_null(self, type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
        current = type_ref
        while current.kind == GraphQLTypeKind.NON_NULL and current.of_type is not None:
            current = current.of_type
        return current

    def _looks_like_email(self, name: str) -> bool:
        return name.lower() in {"email", "emailaddress"}

    def _enum_value_deprecated(self, enum: GraphQLEnum, value: str) -> bool:
        metadata = enum.metadata.get("deprecated_values")
        return isinstance(metadata, list) and value in metadata
