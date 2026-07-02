from yslfuzz.discovery.graphql import GraphQLSDLParser, GraphQLToApiSchemaMapper
from yslfuzz.models import ApiStyle, FieldType, HttpMethod, ParameterLocation


SDL = """
type Query {
  user(id: ID!): User
}

type Mutation {
  createUser(input: CreateUserInput!): User!
}

type User {
  id: ID!
}

input CreateUserInput {
  email: String!
}
"""


def _mapped_schema() -> object:
    graphql_schema = GraphQLSDLParser().parse(SDL)
    return GraphQLToApiSchemaMapper().map(graphql_schema, base_url="http://localhost:8080")


def test_graphql_mapper_maps_query_fields_to_endpoint_like_operations() -> None:
    api_schema = _mapped_schema()
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.graphql_operation_name == "user")

    assert endpoint.api_style == ApiStyle.GRAPHQL
    assert endpoint.method == HttpMethod.POST
    assert endpoint.path == "/graphql"


def test_graphql_mapper_maps_mutation_fields_to_endpoint_like_operations() -> None:
    api_schema = _mapped_schema()
    endpoint = next(
        endpoint
        for endpoint in api_schema.endpoints
        if endpoint.graphql_operation_name == "createUser"
    )

    assert endpoint.graphql_operation_type == "mutation"


def test_graphql_mapper_stores_operation_name_and_type_metadata() -> None:
    api_schema = _mapped_schema()
    endpoint = api_schema.endpoints[0]

    assert endpoint.metadata["graphql_operation_name"] == "user"
    assert endpoint.metadata["graphql_operation_type"] == "query"


def test_graphql_mapper_stores_argument_metadata() -> None:
    api_schema = _mapped_schema()
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.graphql_operation_name == "user")

    assert endpoint.parameters[0].location == ParameterLocation.GRAPHQL_ARGUMENT
    assert endpoint.parameters[0].field_type == FieldType.STRING
    assert endpoint.parameters[0].required is True
    assert endpoint.metadata["graphql_arguments"] == [
        {"name": "id", "type": "ID!", "required": True, "default_value": None}
    ]


def test_graphql_mapper_stores_return_type_metadata() -> None:
    api_schema = _mapped_schema()
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.graphql_operation_name == "user")

    assert endpoint.responses[0].metadata["graphql_return_type"] == "User"
    assert endpoint.metadata["graphql_return_type"] == "User"


def test_graphql_mapper_sets_api_style_or_metadata_to_graphql() -> None:
    api_schema = _mapped_schema()

    assert api_schema.api_style == ApiStyle.GRAPHQL
    assert api_schema.metadata["api_style"] == "graphql"
