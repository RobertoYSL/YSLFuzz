"""Internal GraphQL discovery models."""

from enum import StrEnum
from typing import Any

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel, prefixed_id


class GraphQLOperationType(StrEnum):
    """GraphQL root operation type."""

    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


class GraphQLTypeKind(StrEnum):
    """Supported GraphQL type kinds for discovery."""

    OBJECT = "OBJECT"
    INPUT_OBJECT = "INPUT_OBJECT"
    ENUM = "ENUM"
    SCALAR = "SCALAR"
    LIST = "LIST"
    NON_NULL = "NON_NULL"
    UNION = "UNION"
    INTERFACE = "INTERFACE"


class GraphQLTypeRef(YSLFuzzModel):
    """Reference to a GraphQL named type or wrapper type."""

    kind: GraphQLTypeKind
    name: str | None = None
    of_type: "GraphQLTypeRef | None" = None

    def display(self) -> str:
        """Return GraphQL SDL-style text for this type reference."""
        if self.kind == GraphQLTypeKind.NON_NULL and self.of_type is not None:
            return f"{self.of_type.display()}!"
        if self.kind == GraphQLTypeKind.LIST and self.of_type is not None:
            return f"[{self.of_type.display()}]"
        return self.name or "Unknown"

    def named_type(self) -> str | None:
        """Return the innermost named type, if present."""
        if self.name:
            return self.name
        if self.of_type is not None:
            return self.of_type.named_type()
        return None

    def is_non_null(self) -> bool:
        """Return true when this reference is wrapped in NON_NULL."""
        return self.kind == GraphQLTypeKind.NON_NULL


class GraphQLArgument(YSLFuzzModel):
    """GraphQL field argument."""

    name: str
    type_ref: GraphQLTypeRef
    description: str | None = None
    default_value: Any | None = None


class GraphQLField(YSLFuzzModel):
    """GraphQL object field."""

    name: str
    type_ref: GraphQLTypeRef
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    description: str | None = None


class GraphQLType(YSLFuzzModel):
    """GraphQL object type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.OBJECT
    fields: list[GraphQLField] = Field(default_factory=list)
    description: str | None = None


class GraphQLInputObject(YSLFuzzModel):
    """GraphQL input object type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.INPUT_OBJECT
    fields: list[GraphQLArgument] = Field(default_factory=list)
    description: str | None = None


class GraphQLEnum(YSLFuzzModel):
    """GraphQL enum type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.ENUM
    enum_values: list[str] = Field(default_factory=list)
    description: str | None = None


class GraphQLScalar(YSLFuzzModel):
    """GraphQL scalar type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.SCALAR
    description: str | None = None


class GraphQLUnion(YSLFuzzModel):
    """Discovered GraphQL union type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.UNION
    possible_types: list[GraphQLTypeRef] = Field(default_factory=list)
    description: str | None = None


class GraphQLInterface(YSLFuzzModel):
    """Discovered GraphQL interface type."""

    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.INTERFACE
    fields: list[GraphQLField] = Field(default_factory=list)
    possible_types: list[GraphQLTypeRef] = Field(default_factory=list)
    description: str | None = None


class GraphQLOperation(YSLFuzzModel):
    """GraphQL root operation discovered from Query, Mutation, or Subscription."""

    name: str
    operation_type: GraphQLOperationType
    type_ref: GraphQLTypeRef
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    description: str | None = None


class GraphQLSchema(YSLFuzzModel):
    """Local GraphQL schema discovered from SDL or introspection JSON."""

    schema_id: str = Field(default_factory=lambda: prefixed_id("graphql_schema"))
    source_format: str
    source_location: str | None = None
    query_type_name: str | None = "Query"
    mutation_type_name: str | None = "Mutation"
    subscription_type_name: str | None = "Subscription"
    object_types: list[GraphQLType] = Field(default_factory=list)
    input_objects: list[GraphQLInputObject] = Field(default_factory=list)
    enums: list[GraphQLEnum] = Field(default_factory=list)
    scalars: list[GraphQLScalar] = Field(default_factory=list)
    unions: list[GraphQLUnion] = Field(default_factory=list)
    interfaces: list[GraphQLInterface] = Field(default_factory=list)
    operations: list[GraphQLOperation] = Field(default_factory=list)

    def operation_counts(self) -> dict[str, int]:
        """Return operation counts by root operation type."""
        return {
            "query_count": sum(
                operation.operation_type == GraphQLOperationType.QUERY
                for operation in self.operations
            ),
            "mutation_count": sum(
                operation.operation_type == GraphQLOperationType.MUTATION
                for operation in self.operations
            ),
            "subscription_count": sum(
                operation.operation_type == GraphQLOperationType.SUBSCRIPTION
                for operation in self.operations
            ),
        }

    def type_counts(self) -> dict[str, int]:
        """Return type counts for the discovered schema."""
        return {
            "object_count": len(self.object_types),
            "input_object_count": len(self.input_objects),
            "enum_count": len(self.enums),
            "scalar_count": len(self.scalars),
            "union_count": len(self.unions),
            "interface_count": len(self.interfaces),
        }

    def discovery_summary(self) -> dict[str, Any]:
        """Return a report-safe GraphQL discovery summary without raw schema content."""
        return {
            "api_style": "graphql",
            "graphql_schema_id": self.schema_id,
            "source_format": self.source_format,
            **self.operation_counts(),
            **self.type_counts(),
            "operations": [
                {
                    "name": operation.name,
                    "operation_type": operation.operation_type.value,
                    "argument_count": len(operation.arguments),
                    "return_type": operation.type_ref.display(),
                }
                for operation in self.operations
            ],
        }


GraphQLTypeRef.model_rebuild()
