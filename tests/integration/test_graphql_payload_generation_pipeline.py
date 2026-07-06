from pathlib import Path

from yslfuzz.discovery.graphql import GraphQLSchemaLoader
from yslfuzz.payloads.graphql import GraphQLPayloadGenerator


def test_example_graphql_sdl_schema_produces_query_and_mutation_payloads() -> None:
    schema = GraphQLSchemaLoader().load(Path("examples/graphql/simple_users_schema.graphql"))
    payloads = GraphQLPayloadGenerator().generate(schema)

    operation_types = {payload.metadata["graphql_operation_type"] for payload in payloads}

    assert "query" in operation_types
    assert "mutation" in operation_types
    assert all(payload.body is not None for payload in payloads)
