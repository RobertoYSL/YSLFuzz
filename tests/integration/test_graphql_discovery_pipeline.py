from yslfuzz.discovery.graphql import GraphQLSchemaLoader
from yslfuzz.models import ApiStyle


def test_example_graphql_sdl_schema_parses_and_maps() -> None:
    api_schema = GraphQLSchemaLoader().load_as_api_schema(
        "examples/graphql/simple_users_schema.graphql",
        base_url="http://localhost:8080",
    )

    assert api_schema.api_style == ApiStyle.GRAPHQL
    assert {endpoint.graphql_operation_name for endpoint in api_schema.endpoints} == {
        "user",
        "users",
        "createUser",
    }


def test_example_graphql_introspection_json_parses_and_maps() -> None:
    api_schema = GraphQLSchemaLoader().load_as_api_schema(
        "examples/graphql/simple_users_introspection.json",
        base_url="http://localhost:8080",
    )

    assert api_schema.api_style == ApiStyle.GRAPHQL
    assert len(api_schema.endpoints) == 3
    assert api_schema.created_from[0].source_type == "GRAPHQL_INTROSPECTION"
