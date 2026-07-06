"""Bounded GraphQL selection set generation."""

from yslfuzz.discovery.graphql.models import (
    GraphQLField,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.payloads.graphql.config import GraphQLPayloadConfig


class GraphQLSelectionSetBuilder:
    """Build deterministic, bounded selection sets for GraphQL return types."""

    def __init__(self, config: GraphQLPayloadConfig | None = None) -> None:
        self.config = config or GraphQLPayloadConfig()

    def build(self, return_type: GraphQLTypeRef, schema: GraphQLSchema) -> str:
        """Return a GraphQL selection set string, or an empty string for scalar returns."""
        selection = self._build(return_type, schema, depth=0, path=frozenset())
        return selection or ""

    def selection_depth(self, return_type: GraphQLTypeRef, schema: GraphQLSchema) -> int:
        """Return the maximum object nesting depth selected for metadata."""
        selection = self.build(return_type, schema)
        return selection.count("{")

    def _build(
        self,
        type_ref: GraphQLTypeRef,
        schema: GraphQLSchema,
        *,
        depth: int,
        path: frozenset[str],
    ) -> str | None:
        named_type = self._named_return_type(type_ref)
        object_type = self._object_type(named_type, schema)
        if object_type is None:
            return None
        if depth >= self.config.max_selection_depth or object_type.name in path:
            scalar_fields = self._scalar_fields(object_type, schema)
            return self._format_selection([field.name for field in scalar_fields])

        selected: list[str] = []
        if self.config.include_typename:
            selected.append("__typename")

        for field in object_type.fields:
            if len(selected) >= self.config.max_fields_per_selection:
                break
            if self._is_deprecated(field) and not self.config.include_deprecated_fields:
                continue
            if self._field_has_required_arguments(field):
                continue
            child_type = self._named_return_type(field.type_ref)
            child_object = self._object_type(child_type, schema)
            if child_object is None:
                selected.append(field.name)
                continue
            child_selection = self._build(
                field.type_ref,
                schema,
                depth=depth + 1,
                path=path | {object_type.name},
            )
            if child_selection:
                selected.append(f"{field.name} {child_selection}")

        return self._format_selection(selected)

    def _format_selection(self, selected: list[str]) -> str | None:
        if not selected:
            return None
        return "{ " + " ".join(selected) + " }"

    def _scalar_fields(self, object_type: GraphQLType, schema: GraphQLSchema) -> list[GraphQLField]:
        fields: list[GraphQLField] = []
        for field in object_type.fields:
            if self._is_deprecated(field) and not self.config.include_deprecated_fields:
                continue
            if self._field_has_required_arguments(field):
                continue
            if self._object_type(self._named_return_type(field.type_ref), schema) is None:
                fields.append(field)
            if len(fields) >= self.config.max_fields_per_selection:
                break
        return fields

    def _named_return_type(self, type_ref: GraphQLTypeRef) -> str | None:
        current = type_ref
        while current.kind in {GraphQLTypeKind.NON_NULL, GraphQLTypeKind.LIST} and current.of_type is not None:
            current = current.of_type
        return current.named_type()

    def _object_type(self, name: str | None, schema: GraphQLSchema) -> GraphQLType | None:
        if name is None:
            return None
        return next((type_definition for type_definition in schema.object_types if type_definition.name == name), None)

    def _field_has_required_arguments(self, field: GraphQLField) -> bool:
        return any(argument.type_ref.is_non_null() for argument in field.arguments)

    def _is_deprecated(self, field: GraphQLField) -> bool:
        return bool(field.metadata.get("deprecated") or field.metadata.get("isDeprecated"))
