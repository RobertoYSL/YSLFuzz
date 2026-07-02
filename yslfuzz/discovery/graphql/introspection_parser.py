"""GraphQL introspection JSON parser for the discovery MVP."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from yslfuzz.discovery.graphql.models import (
    GraphQLArgument,
    GraphQLEnum,
    GraphQLField,
    GraphQLInputObject,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLScalar,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)


class GraphQLIntrospectionParseError(ValueError):
    """Raised when a GraphQL introspection document cannot be parsed."""


class GraphQLIntrospectionParser:
    """Parse local GraphQL introspection JSON dictionaries."""

    def parse(self, data: Mapping[str, Any]) -> GraphQLSchema:
        """Parse a standard minimal introspection result into GraphQLSchema."""
        schema_data = self._schema_mapping(data)
        types_raw = self._sequence(schema_data.get("types"), "__schema.types")

        query_type_name = self._type_name(schema_data.get("queryType"))
        mutation_type_name = self._type_name(schema_data.get("mutationType"))
        subscription_type_name = self._type_name(schema_data.get("subscriptionType"))

        object_types: list[GraphQLType] = []
        input_objects: list[GraphQLInputObject] = []
        enums: list[GraphQLEnum] = []
        scalars: list[GraphQLScalar] = []

        for item in types_raw:
            type_data = self._mapping(item, "__schema.types[]")
            name = self._required_string(type_data.get("name"), "GraphQL type name")
            kind = self._kind(type_data.get("kind"))
            if name.startswith("__"):
                continue
            if kind == GraphQLTypeKind.OBJECT:
                object_types.append(
                    GraphQLType(
                        name=name,
                        fields=self._fields(type_data.get("fields")),
                        description=self._optional_string(type_data.get("description")),
                    )
                )
            elif kind == GraphQLTypeKind.INPUT_OBJECT:
                input_objects.append(
                    GraphQLInputObject(
                        name=name,
                        fields=self._input_fields(type_data.get("inputFields")),
                        description=self._optional_string(type_data.get("description")),
                    )
                )
            elif kind == GraphQLTypeKind.ENUM:
                enums.append(
                    GraphQLEnum(
                        name=name,
                        enum_values=self._enum_values(type_data.get("enumValues")),
                        description=self._optional_string(type_data.get("description")),
                    )
                )
            elif kind == GraphQLTypeKind.SCALAR:
                scalars.append(
                    GraphQLScalar(
                        name=name,
                        description=self._optional_string(type_data.get("description")),
                    )
                )

        schema = GraphQLSchema(
            source_format="introspection_json",
            query_type_name=query_type_name,
            mutation_type_name=mutation_type_name,
            subscription_type_name=subscription_type_name,
            object_types=object_types,
            input_objects=input_objects,
            enums=enums,
            scalars=scalars,
        )
        schema.operations = self._extract_operations(schema)
        return schema

    def _schema_mapping(self, data: Mapping[str, Any]) -> Mapping[str, Any]:
        if isinstance(data.get("__schema"), Mapping):
            return self._mapping(data["__schema"], "__schema")
        nested_data = data.get("data")
        if isinstance(nested_data, Mapping) and isinstance(nested_data.get("__schema"), Mapping):
            return self._mapping(nested_data["__schema"], "data.__schema")
        raise GraphQLIntrospectionParseError("Introspection JSON must contain __schema")

    def _fields(self, raw: Any) -> list[GraphQLField]:
        if raw is None:
            return []
        fields: list[GraphQLField] = []
        for item in self._sequence(raw, "fields"):
            field_data = self._mapping(item, "fields[]")
            fields.append(
                GraphQLField(
                    name=self._required_string(field_data.get("name"), "GraphQL field name"),
                    type_ref=self._type_ref(field_data.get("type")),
                    arguments=self._arguments(field_data.get("args")),
                    description=self._optional_string(field_data.get("description")),
                )
            )
        return fields

    def _input_fields(self, raw: Any) -> list[GraphQLArgument]:
        if raw is None:
            return []
        return [
            self._argument(self._mapping(item, "inputFields[]"))
            for item in self._sequence(raw, "inputFields")
        ]

    def _arguments(self, raw: Any) -> list[GraphQLArgument]:
        if raw is None:
            return []
        return [
            self._argument(self._mapping(item, "args[]"))
            for item in self._sequence(raw, "args")
        ]

    def _argument(self, data: Mapping[str, Any]) -> GraphQLArgument:
        return GraphQLArgument(
            name=self._required_string(data.get("name"), "GraphQL argument name"),
            type_ref=self._type_ref(data.get("type")),
            description=self._optional_string(data.get("description")),
            default_value=data.get("defaultValue"),
        )

    def _enum_values(self, raw: Any) -> list[str]:
        if raw is None:
            return []
        values: list[str] = []
        for item in self._sequence(raw, "enumValues"):
            value_data = self._mapping(item, "enumValues[]")
            values.append(self._required_string(value_data.get("name"), "GraphQL enum value name"))
        return values

    def _type_ref(self, raw: Any) -> GraphQLTypeRef:
        data = self._mapping(raw, "GraphQL type reference")
        kind = self._kind(data.get("kind"))
        name = self._optional_string(data.get("name"))
        of_type_raw = data.get("ofType")
        of_type = self._type_ref(of_type_raw) if isinstance(of_type_raw, Mapping) else None
        if kind in {GraphQLTypeKind.NON_NULL, GraphQLTypeKind.LIST} and of_type is None:
            raise GraphQLIntrospectionParseError(f"{kind.value} type reference requires ofType")
        return GraphQLTypeRef(kind=kind, name=name, of_type=of_type)

    def _extract_operations(self, schema: GraphQLSchema) -> list[GraphQLOperation]:
        types_by_name = {type_definition.name: type_definition for type_definition in schema.object_types}
        operations: list[GraphQLOperation] = []
        for root_name, operation_type in (
            (schema.query_type_name, GraphQLOperationType.QUERY),
            (schema.mutation_type_name, GraphQLOperationType.MUTATION),
            (schema.subscription_type_name, GraphQLOperationType.SUBSCRIPTION),
        ):
            if root_name is None or root_name not in types_by_name:
                continue
            for field in types_by_name[root_name].fields:
                operations.append(
                    GraphQLOperation(
                        name=field.name,
                        operation_type=operation_type,
                        type_ref=field.type_ref,
                        arguments=field.arguments,
                        description=field.description,
                    )
                )
        return operations

    def _kind(self, value: Any) -> GraphQLTypeKind:
        if not isinstance(value, str):
            raise GraphQLIntrospectionParseError("GraphQL type kind must be a string")
        try:
            return GraphQLTypeKind(value)
        except ValueError as exc:
            raise GraphQLIntrospectionParseError(f"Unsupported GraphQL type kind: {value}") from exc

    def _type_name(self, raw: Any) -> str | None:
        if raw is None:
            return None
        data = self._mapping(raw, "GraphQL root type reference")
        return self._optional_string(data.get("name"))

    def _mapping(self, value: Any, label: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise GraphQLIntrospectionParseError(f"{label} must be an object")
        return value

    def _sequence(self, value: Any, label: str) -> Sequence[Any]:
        if not isinstance(value, list):
            raise GraphQLIntrospectionParseError(f"{label} must be a list")
        return value

    def _required_string(self, value: Any, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise GraphQLIntrospectionParseError(f"{label} must be a non-empty string")
        return value

    def _optional_string(self, value: Any) -> str | None:
        return value if isinstance(value, str) else None
