import json
from pathlib import Path

from yslfuzz.discovery.graphql import GraphQLIntrospectionParser


def _example_data() -> dict[str, object]:
    return json.loads(Path("examples/graphql/simple_users_introspection.json").read_text(encoding="utf-8"))


def test_introspection_parser_parses_query_type() -> None:
    schema = GraphQLIntrospectionParser().parse(_example_data())

    assert schema.query_type_name == "Query"
    assert schema.operation_counts()["query_count"] == 2


def test_introspection_parser_parses_mutation_type() -> None:
    schema = GraphQLIntrospectionParser().parse(_example_data())

    assert schema.mutation_type_name == "Mutation"
    assert schema.operation_counts()["mutation_count"] == 1


def test_introspection_parser_parses_object_fields() -> None:
    schema = GraphQLIntrospectionParser().parse(_example_data())
    user = next(type_definition for type_definition in schema.object_types if type_definition.name == "User")

    assert [field.name for field in user.fields] == ["id", "email", "name", "role"]


def test_introspection_parser_parses_input_fields() -> None:
    schema = GraphQLIntrospectionParser().parse(_example_data())
    create_user_input = next(item for item in schema.input_objects if item.name == "CreateUserInput")

    assert [field.name for field in create_user_input.fields] == ["email", "name"]


def test_introspection_parser_parses_enum_values() -> None:
    schema = GraphQLIntrospectionParser().parse(_example_data())
    role = next(item for item in schema.enums if item.name == "UserRole")

    assert role.enum_values == ["USER", "ADMIN"]
