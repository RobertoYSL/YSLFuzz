from yslfuzz.discovery.graphql import (
    GraphQLArgument,
    GraphQLInputObject,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLSchema,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.payloads.graphql import GraphQLPayloadConfig, GraphQLVariableGenerator


def scalar_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=name)


def non_null(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.NON_NULL, of_type=type_ref)


def list_ref(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.LIST, of_type=type_ref)


def operation_with(argument: GraphQLArgument) -> GraphQLOperation:
    return GraphQLOperation(
        name="user",
        operation_type=GraphQLOperationType.QUERY,
        type_ref=scalar_ref("String"),
        arguments=[argument],
    )


def test_variable_generator_handles_required_scalar_argument() -> None:
    argument = GraphQLArgument(name="id", type_ref=non_null(scalar_ref("ID")))
    generated = GraphQLVariableGenerator().generate_arguments(
        operation_with(argument),
        GraphQLSchema(source_format="sdl"),
    )

    assert generated.variable_definitions == ["$id: ID!"]
    assert generated.argument_bindings == ["id: $id"]
    assert generated.variables == {"id": "yslfuzz-id-001"}


def test_variable_generator_handles_optional_scalar_argument() -> None:
    argument = GraphQLArgument(name="limit", type_ref=scalar_ref("Int"))
    generated = GraphQLVariableGenerator().generate_arguments(
        operation_with(argument),
        GraphQLSchema(source_format="sdl"),
    )

    assert generated.variables == {"limit": 1}


def test_variable_generator_handles_list_argument_with_bounded_size() -> None:
    argument = GraphQLArgument(name="ids", type_ref=list_ref(non_null(scalar_ref("ID"))))
    generated = GraphQLVariableGenerator(
        GraphQLPayloadConfig(max_list_items=1),
    ).generate_arguments(operation_with(argument), GraphQLSchema(source_format="sdl"))

    assert generated.variables == {"ids": ["yslfuzz-id-001"]}


def test_variable_generator_handles_input_object_argument() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        input_objects=[
            GraphQLInputObject(
                name="CreateUserInput",
                fields=[
                    GraphQLArgument(name="email", type_ref=non_null(scalar_ref("String"))),
                    GraphQLArgument(name="name", type_ref=scalar_ref("String")),
                ],
            )
        ],
    )
    argument = GraphQLArgument(
        name="input",
        type_ref=non_null(GraphQLTypeRef(kind=GraphQLTypeKind.INPUT_OBJECT, name="CreateUserInput")),
    )

    generated = GraphQLVariableGenerator().generate_arguments(operation_with(argument), schema)

    assert generated.variables == {
        "input": {"email": "yslfuzz-string", "name": "yslfuzz-string"}
    }


def test_variable_generator_handles_nested_input_object_with_depth_limit() -> None:
    nested_ref = GraphQLTypeRef(kind=GraphQLTypeKind.INPUT_OBJECT, name="NestedInput")
    schema = GraphQLSchema(
        source_format="sdl",
        input_objects=[
            GraphQLInputObject(
                name="RootInput",
                fields=[GraphQLArgument(name="nested", type_ref=nested_ref)],
            ),
            GraphQLInputObject(
                name="NestedInput",
                fields=[GraphQLArgument(name="value", type_ref=scalar_ref("String"))],
            ),
        ],
    )
    argument = GraphQLArgument(
        name="input",
        type_ref=GraphQLTypeRef(kind=GraphQLTypeKind.INPUT_OBJECT, name="RootInput"),
    )

    generated = GraphQLVariableGenerator(
        GraphQLPayloadConfig(max_input_depth=1),
    ).generate_arguments(operation_with(argument), schema)

    assert generated.variables == {"input": {"nested": {}}}


def test_variable_generator_can_inline_literals() -> None:
    argument = GraphQLArgument(name="id", type_ref=non_null(scalar_ref("ID")))
    generated = GraphQLVariableGenerator(
        GraphQLPayloadConfig(generate_variables=False),
    ).generate_arguments(operation_with(argument), GraphQLSchema(source_format="sdl"))

    assert generated.variable_definitions == []
    assert generated.argument_bindings == ['id: "yslfuzz-id-001"']
    assert generated.variables == {}
