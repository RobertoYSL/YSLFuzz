from yslfuzz.discovery.graphql import (
    GraphQLOperationType,
    GraphQLSDLParser,
    GraphQLTypeKind,
)


SDL = """
# comments are ignored
directive @upper on FIELD_DEFINITION

type Query {
  user(id: ID!): User
  users(limit: Int): [User!]! @deprecated
  status: Status!
}

type Mutation {
  createUser(input: CreateUserInput!): User!
}

type User {
  id: ID!
  email: String!
  name: String
}

input CreateUserInput {
  email: String!
  name: String
}

enum Status {
  ACTIVE
  DISABLED @deprecated
}
"""


def test_sdl_parser_parses_object_type() -> None:
    schema = GraphQLSDLParser().parse(SDL)

    assert any(type_definition.name == "User" for type_definition in schema.object_types)


def test_sdl_parser_parses_input_object_type() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    input_object = next(item for item in schema.input_objects if item.name == "CreateUserInput")

    assert [field.name for field in input_object.fields] == ["email", "name"]


def test_sdl_parser_parses_enum_type() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    enum = next(item for item in schema.enums if item.name == "Status")

    assert enum.enum_values == ["ACTIVE", "DISABLED"]


def test_sdl_parser_parses_scalar_field() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    user = next(item for item in schema.object_types if item.name == "User")
    name_field = next(field for field in user.fields if field.name == "name")

    assert name_field.type_ref.display() == "String"


def test_sdl_parser_parses_list_type() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    operation = next(operation for operation in schema.operations if operation.name == "users")

    assert operation.type_ref.display() == "[User!]!"
    assert operation.type_ref.kind == GraphQLTypeKind.NON_NULL


def test_sdl_parser_parses_non_null_type() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    operation = next(operation for operation in schema.operations if operation.name == "user")
    argument = operation.arguments[0]

    assert argument.type_ref.display() == "ID!"
    assert argument.type_ref.is_non_null() is True


def test_sdl_parser_parses_query_operations() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    query_names = {
        operation.name
        for operation in schema.operations
        if operation.operation_type == GraphQLOperationType.QUERY
    }

    assert query_names == {"user", "users", "status"}


def test_sdl_parser_parses_mutation_operations() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    mutation = next(
        operation
        for operation in schema.operations
        if operation.operation_type == GraphQLOperationType.MUTATION
    )

    assert mutation.name == "createUser"


def test_sdl_parser_parses_field_arguments() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    operation = next(operation for operation in schema.operations if operation.name == "createUser")

    assert operation.arguments[0].name == "input"
    assert operation.arguments[0].type_ref.display() == "CreateUserInput!"


def test_sdl_parser_ignores_comments() -> None:
    schema = GraphQLSDLParser().parse(SDL)

    assert schema.operation_counts()["query_count"] == 3


def test_sdl_parser_handles_directives_conservatively() -> None:
    schema = GraphQLSDLParser().parse(SDL)
    users = next(operation for operation in schema.operations if operation.name == "users")

    assert users.type_ref.display() == "[User!]!"
