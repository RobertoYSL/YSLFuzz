"""Conservative GraphQL SDL parser for the discovery MVP."""

from __future__ import annotations

import re

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


class GraphQLSDLParseError(ValueError):
    """Raised when GraphQL SDL cannot be parsed by the MVP subset parser."""


class GraphQLSDLParser:
    """Parse a limited, local GraphQL SDL subset into GraphQL discovery models."""

    _definition_pattern = re.compile(
        r"\b(?P<kind>type|input|enum)\s+(?P<name>[_A-Za-z][_0-9A-Za-z]*)[^{]*"
        r"\{(?P<body>.*?)\}",
        re.DOTALL,
    )
    _scalar_pattern = re.compile(r"\bscalar\s+(?P<name>[_A-Za-z][_0-9A-Za-z]*)\b")
    _field_pattern = re.compile(
        r"(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*"
        r"(?P<args>\([^)]*\))?\s*:\s*(?P<type>[!\[\]_0-9A-Za-z]+)"
    )
    _argument_pattern = re.compile(
        r"(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*:\s*(?P<type>[!\[\]_0-9A-Za-z]+)"
    )
    _name_pattern = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")

    def parse(self, text: str) -> GraphQLSchema:
        """Parse GraphQL SDL text into a local GraphQLSchema model."""
        if not text.strip():
            raise GraphQLSDLParseError("GraphQL SDL document is empty")

        cleaned = self._strip_comments_and_descriptions(text)
        object_types: list[GraphQLType] = []
        input_objects: list[GraphQLInputObject] = []
        enums: list[GraphQLEnum] = []

        for match in self._definition_pattern.finditer(cleaned):
            kind = match.group("kind")
            name = match.group("name")
            body = self._strip_directives(match.group("body"))
            if kind == "type":
                object_types.append(GraphQLType(name=name, fields=self._parse_fields(body)))
            elif kind == "input":
                input_objects.append(
                    GraphQLInputObject(name=name, fields=self._parse_input_fields(body))
                )
            elif kind == "enum":
                enums.append(GraphQLEnum(name=name, enum_values=self._parse_enum_values(body)))

        scalar_names = {
            match.group("name")
            for match in self._scalar_pattern.finditer(self._strip_definition_bodies(cleaned))
        }
        scalar_names.update({"ID", "String", "Int", "Float", "Boolean"})
        scalars = [GraphQLScalar(name=name) for name in sorted(scalar_names)]

        if not object_types and not input_objects and not enums and not scalar_names:
            raise GraphQLSDLParseError("No supported GraphQL SDL definitions were found")

        schema = GraphQLSchema(
            source_format="sdl",
            object_types=object_types,
            input_objects=input_objects,
            enums=enums,
            scalars=scalars,
        )
        schema.operations = self._extract_operations(schema)
        return schema

    def _parse_fields(self, body: str) -> list[GraphQLField]:
        fields: list[GraphQLField] = []
        for match in self._field_pattern.finditer(body):
            fields.append(
                GraphQLField(
                    name=match.group("name"),
                    arguments=self._parse_arguments(match.group("args")),
                    type_ref=self._parse_type_ref(match.group("type")),
                )
            )
        return fields

    def _parse_input_fields(self, body: str) -> list[GraphQLArgument]:
        return [
            GraphQLArgument(name=match.group("name"), type_ref=self._parse_type_ref(match.group("type")))
            for match in self._field_pattern.finditer(body)
        ]

    def _parse_arguments(self, raw: str | None) -> list[GraphQLArgument]:
        if raw is None:
            return []
        argument_text = self._strip_directives(raw.strip()[1:-1])
        return [
            GraphQLArgument(name=match.group("name"), type_ref=self._parse_type_ref(match.group("type")))
            for match in self._argument_pattern.finditer(argument_text)
        ]

    def _parse_enum_values(self, body: str) -> list[str]:
        values: list[str] = []
        for raw_line in body.splitlines():
            line = self._strip_directives(raw_line).strip()
            if not line:
                continue
            for name in self._name_pattern.findall(line):
                if name not in values:
                    values.append(name)
        return values

    def _parse_type_ref(self, value: str) -> GraphQLTypeRef:
        text = value.strip()
        if not text:
            raise GraphQLSDLParseError("GraphQL type reference is empty")
        if text.endswith("!"):
            return GraphQLTypeRef(
                kind=GraphQLTypeKind.NON_NULL,
                of_type=self._parse_type_ref(text[:-1]),
            )
        if text.startswith("[") and text.endswith("]"):
            return GraphQLTypeRef(
                kind=GraphQLTypeKind.LIST,
                of_type=self._parse_type_ref(text[1:-1]),
            )
        if not self._name_pattern.fullmatch(text):
            raise GraphQLSDLParseError(f"Unsupported GraphQL type reference: {value}")
        return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=text)

    def _extract_operations(self, schema: GraphQLSchema) -> list[GraphQLOperation]:
        types_by_name = {type_definition.name: type_definition for type_definition in schema.object_types}
        operations: list[GraphQLOperation] = []
        root_specs = (
            (schema.query_type_name, GraphQLOperationType.QUERY),
            (schema.mutation_type_name, GraphQLOperationType.MUTATION),
            (schema.subscription_type_name, GraphQLOperationType.SUBSCRIPTION),
        )
        for root_name, operation_type in root_specs:
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

    def _strip_comments_and_descriptions(self, text: str) -> str:
        without_triple_descriptions = re.sub(r'"""[\s\S]*?"""', "", text)
        without_single_descriptions = re.sub(r'"[^"\n]*"', "", without_triple_descriptions)
        return "\n".join(line.split("#", 1)[0] for line in without_single_descriptions.splitlines())

    def _strip_directives(self, text: str) -> str:
        return re.sub(r"@[_A-Za-z][_0-9A-Za-z]*(\([^)]*\))?", "", text)

    def _strip_definition_bodies(self, text: str) -> str:
        return self._definition_pattern.sub("", text)
