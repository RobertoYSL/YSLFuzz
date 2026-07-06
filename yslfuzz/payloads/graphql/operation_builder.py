"""GraphQL operation document builder."""

from dataclasses import dataclass
from typing import Any

from yslfuzz.discovery.graphql.models import GraphQLOperation, GraphQLSchema
from yslfuzz.payloads.graphql.config import GraphQLPayloadConfig
from yslfuzz.payloads.graphql.selection import GraphQLSelectionSetBuilder
from yslfuzz.payloads.graphql.variables import GraphQLVariableGenerator


@dataclass(frozen=True)
class GraphQLOperationPayload:
    """Built GraphQL operation payload ready for future HTTP execution."""

    query: str
    variables: dict[str, Any]
    operationName: str
    operation_type: str
    operation_field_name: str
    return_type: str
    variable_names: list[str]
    selection_depth: int

    def body(self) -> dict[str, Any]:
        """Return GraphQL-over-HTTP JSON body shape."""
        return {
            "query": self.query,
            "variables": self.variables,
            "operationName": self.operationName,
        }


class GraphQLOperationBuilder:
    """Build readable GraphQL query and mutation documents."""

    def __init__(
        self,
        config: GraphQLPayloadConfig | None = None,
        variable_generator: GraphQLVariableGenerator | None = None,
        selection_builder: GraphQLSelectionSetBuilder | None = None,
    ) -> None:
        self.config = config or GraphQLPayloadConfig()
        self.variable_generator = variable_generator or GraphQLVariableGenerator(self.config)
        self.selection_builder = selection_builder or GraphQLSelectionSetBuilder(self.config)

    def build(self, operation: GraphQLOperation, schema: GraphQLSchema) -> GraphQLOperationPayload:
        """Build a GraphQL operation payload from a discovered root operation."""
        variable_set = self.variable_generator.generate_arguments(operation, schema)
        operation_name = self._operation_name(operation.name)
        variable_definitions = (
            "(" + ", ".join(variable_set.variable_definitions) + ")"
            if variable_set.variable_definitions
            else ""
        )
        argument_bindings = (
            "(" + ", ".join(variable_set.argument_bindings) + ")"
            if variable_set.argument_bindings
            else ""
        )
        selection = self.selection_builder.build(operation.type_ref, schema)
        field_document = f"{operation.name}{argument_bindings}"
        if selection:
            field_document = f"{field_document} {selection}"
        query = (
            f"{operation.operation_type.value} {operation_name}{variable_definitions} "
            f"{{ {field_document} }}"
        )
        return GraphQLOperationPayload(
            query=query,
            variables=variable_set.variables,
            operationName=operation_name,
            operation_type=operation.operation_type.value,
            operation_field_name=operation.name,
            return_type=operation.type_ref.display(),
            variable_names=variable_set.variable_names,
            selection_depth=self.selection_builder.selection_depth(operation.type_ref, schema),
        )

    def _operation_name(self, operation_field_name: str) -> str:
        cleaned = "".join(character for character in operation_field_name.title() if character.isalnum())
        return f"{self.config.operation_name_prefix}{cleaned or 'Operation'}"
