from yslfuzz.discovery.graphql import (
    GraphQLField,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)


def test_graphql_models_validate_minimal_schema() -> None:
    type_ref = GraphQLTypeRef(
        kind=GraphQLTypeKind.NON_NULL,
        of_type=GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name="String"),
    )
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[GraphQLType(name="Query", fields=[GraphQLField(name="health", type_ref=type_ref)])],
        operations=[
            GraphQLOperation(
                name="health",
                operation_type=GraphQLOperationType.QUERY,
                type_ref=type_ref,
            )
        ],
    )

    assert schema.operation_counts()["query_count"] == 1
    assert schema.type_counts()["object_count"] == 1
    assert type_ref.display() == "String!"
