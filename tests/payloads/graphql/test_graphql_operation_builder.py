from yslfuzz.discovery.graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.payloads.graphql import GraphQLOperationBuilder


def scalar_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=name)


def object_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.OBJECT, name=name)


def non_null(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.NON_NULL, of_type=type_ref)


def schema() -> GraphQLSchema:
    return GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(name="id", type_ref=scalar_ref("ID")),
                    GraphQLField(name="email", type_ref=scalar_ref("String")),
                ],
            )
        ],
    )


def test_operation_builder_creates_valid_query_document() -> None:
    operation = GraphQLOperation(
        name="user",
        operation_type=GraphQLOperationType.QUERY,
        type_ref=object_ref("User"),
        arguments=[GraphQLArgument(name="id", type_ref=non_null(scalar_ref("ID")))],
    )

    payload = GraphQLOperationBuilder().build(operation, schema())

    assert payload.operationName == "YSLFuzzUser"
    assert payload.query == (
        "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }"
    )
    assert payload.variables == {"id": "yslfuzz-id-001"}


def test_operation_builder_creates_valid_mutation_document() -> None:
    operation = GraphQLOperation(
        name="createUser",
        operation_type=GraphQLOperationType.MUTATION,
        type_ref=non_null(object_ref("User")),
    )

    payload = GraphQLOperationBuilder().build(operation, schema())

    assert payload.operationName == "YSLFuzzCreateuser"
    assert payload.query == "mutation YSLFuzzCreateuser { createUser { id email } }"


def test_operation_builder_handles_scalar_return_without_selection() -> None:
    operation = GraphQLOperation(
        name="health",
        operation_type=GraphQLOperationType.QUERY,
        type_ref=scalar_ref("String"),
    )

    payload = GraphQLOperationBuilder().build(operation, schema())

    assert payload.query == "query YSLFuzzHealth { health }"
