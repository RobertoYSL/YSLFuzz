from yslfuzz.discovery.graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.payloads.graphql import GraphQLPayloadConfig, GraphQLSelectionSetBuilder


def scalar_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=name)


def object_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.OBJECT, name=name)


def test_selection_builder_selects_scalar_fields() -> None:
    schema = GraphQLSchema(
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

    assert GraphQLSelectionSetBuilder().build(object_ref("User"), schema) == "{ id email }"


def test_selection_builder_handles_nested_object_fields_within_depth_limit() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(name="id", type_ref=scalar_ref("ID")),
                    GraphQLField(name="profile", type_ref=object_ref("Profile")),
                ],
            ),
            GraphQLType(
                name="Profile",
                fields=[GraphQLField(name="displayName", type_ref=scalar_ref("String"))],
            ),
        ],
    )

    assert (
        GraphQLSelectionSetBuilder(GraphQLPayloadConfig(max_selection_depth=2)).build(
            object_ref("User"),
            schema,
        )
        == "{ id profile { displayName } }"
    )


def test_selection_builder_avoids_cycles() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(name="id", type_ref=scalar_ref("ID")),
                    GraphQLField(name="manager", type_ref=object_ref("User")),
                ],
            )
        ],
    )

    assert GraphQLSelectionSetBuilder().build(object_ref("User"), schema) == "{ id manager { id } }"


def test_selection_builder_respects_max_fields_per_selection() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(name="id", type_ref=scalar_ref("ID")),
                    GraphQLField(name="email", type_ref=scalar_ref("String")),
                    GraphQLField(name="name", type_ref=scalar_ref("String")),
                ],
            )
        ],
    )

    assert (
        GraphQLSelectionSetBuilder(GraphQLPayloadConfig(max_fields_per_selection=2)).build(
            object_ref("User"),
            schema,
        )
        == "{ id email }"
    )


def test_selection_builder_skips_deprecated_fields_if_metadata_is_available() -> None:
    deprecated = GraphQLField(name="oldEmail", type_ref=scalar_ref("String"))
    deprecated.metadata["deprecated"] = True
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    deprecated,
                    GraphQLField(name="email", type_ref=scalar_ref("String")),
                ],
            )
        ],
    )

    assert GraphQLSelectionSetBuilder().build(object_ref("User"), schema) == "{ email }"


def test_selection_builder_skips_fields_with_required_arguments() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(
                        name="avatar",
                        type_ref=scalar_ref("String"),
                        arguments=[
                            GraphQLArgument(
                                name="size",
                                type_ref=GraphQLTypeRef(
                                    kind=GraphQLTypeKind.NON_NULL,
                                    of_type=scalar_ref("Int"),
                                ),
                            )
                        ],
                    ),
                    GraphQLField(name="email", type_ref=scalar_ref("String")),
                ],
            )
        ],
    )

    assert GraphQLSelectionSetBuilder().build(object_ref("User"), schema) == "{ email }"
