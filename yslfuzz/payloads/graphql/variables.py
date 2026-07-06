"""GraphQL operation variable generation."""

from dataclasses import dataclass
from typing import Any

from yslfuzz.discovery.graphql.models import (
    GraphQLArgument,
    GraphQLInputObject,
    GraphQLOperation,
    GraphQLSchema,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.payloads.graphql.config import GraphQLPayloadConfig
from yslfuzz.payloads.graphql.scalars import GraphQLScalarValueGenerator


@dataclass(frozen=True)
class GraphQLVariableSet:
    """Generated GraphQL variables and document fragments for operation arguments."""

    variable_definitions: list[str]
    argument_bindings: list[str]
    variables: dict[str, Any]
    variable_names: list[str]


class GraphQLVariableGenerator:
    """Generate deterministic variables for GraphQL operation arguments."""

    def __init__(
        self,
        config: GraphQLPayloadConfig | None = None,
        scalar_generator: GraphQLScalarValueGenerator | None = None,
    ) -> None:
        self.config = config or GraphQLPayloadConfig()
        self.scalar_generator = scalar_generator or GraphQLScalarValueGenerator()

    def generate_arguments(
        self,
        operation: GraphQLOperation,
        schema: GraphQLSchema,
    ) -> GraphQLVariableSet:
        """Generate variable definitions, argument bindings, and variable values."""
        variable_definitions: list[str] = []
        argument_bindings: list[str] = []
        variables: dict[str, Any] = {}

        for argument in operation.arguments:
            value = self.generate_value(argument.type_ref, schema)
            if self.config.generate_variables:
                variable_definitions.append(f"${argument.name}: {argument.type_ref.display()}")
                argument_bindings.append(f"{argument.name}: ${argument.name}")
                variables[argument.name] = value
            else:
                literal = self.scalar_generator.literal(value, argument.type_ref, schema)
                argument_bindings.append(f"{argument.name}: {literal}")

        return GraphQLVariableSet(
            variable_definitions=variable_definitions,
            argument_bindings=argument_bindings,
            variables=variables,
            variable_names=list(variables),
        )

    def generate_value(
        self,
        type_ref: GraphQLTypeRef,
        schema: GraphQLSchema,
        *,
        depth: int = 0,
        seen_input_types: frozenset[str] = frozenset(),
    ) -> Any:
        """Generate a deterministic value for an argument or input object field."""
        unwrapped = self._unwrap_non_null(type_ref)
        if unwrapped.kind == GraphQLTypeKind.LIST and unwrapped.of_type is not None:
            return [
                self.generate_value(
                    unwrapped.of_type,
                    schema,
                    depth=depth,
                    seen_input_types=seen_input_types,
                )
                for _ in range(self.config.max_list_items)
            ]

        named_type = unwrapped.named_type()
        input_object = self._input_object(named_type, schema)
        if input_object is None:
            return self.scalar_generator.generate(unwrapped, schema)
        if depth >= self.config.max_input_depth or input_object.name in seen_input_types:
            return {}
        return self._generate_input_object(
            input_object,
            schema,
            depth=depth + 1,
            seen_input_types=seen_input_types | {input_object.name},
        )

    def _generate_input_object(
        self,
        input_object: GraphQLInputObject,
        schema: GraphQLSchema,
        *,
        depth: int,
        seen_input_types: frozenset[str],
    ) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for field in input_object.fields[: self.config.max_fields_per_selection]:
            if not self._should_include_input_field(field):
                continue
            values[field.name] = self.generate_value(
                field.type_ref,
                schema,
                depth=depth,
                seen_input_types=seen_input_types,
            )
        return values

    def _should_include_input_field(self, field: GraphQLArgument) -> bool:
        if self._is_deprecated(field) and not self.config.include_deprecated_fields:
            return False
        return True

    def _input_object(self, name: str | None, schema: GraphQLSchema) -> GraphQLInputObject | None:
        if name is None:
            return None
        return next((input_object for input_object in schema.input_objects if input_object.name == name), None)

    def _unwrap_non_null(self, type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
        current = type_ref
        while current.kind == GraphQLTypeKind.NON_NULL and current.of_type is not None:
            current = current.of_type
        return current

    def _is_deprecated(self, argument: GraphQLArgument) -> bool:
        return bool(argument.metadata.get("deprecated") or argument.metadata.get("isDeprecated"))
