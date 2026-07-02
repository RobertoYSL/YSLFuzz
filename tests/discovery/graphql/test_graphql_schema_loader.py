from pathlib import Path

import pytest

from yslfuzz.discovery.graphql import GraphQLSchemaLoadError, GraphQLSchemaLoader


def test_schema_loader_detects_sdl_file() -> None:
    schema = GraphQLSchemaLoader().load("examples/graphql/simple_users_schema.graphql")

    assert schema.source_format == "sdl"
    assert schema.operation_counts()["query_count"] == 2


def test_schema_loader_detects_introspection_json_file() -> None:
    schema = GraphQLSchemaLoader().load("examples/graphql/simple_users_introspection.json")

    assert schema.source_format == "introspection_json"
    assert schema.operation_counts()["mutation_count"] == 1


def test_schema_loader_rejects_missing_file_clearly(tmp_path: Path) -> None:
    with pytest.raises(GraphQLSchemaLoadError, match="does not exist"):
        GraphQLSchemaLoader().load(tmp_path / "missing.graphql")


def test_schema_loader_rejects_unsupported_file_clearly(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.txt"
    schema_path.write_text("type Query { ping: String }", encoding="utf-8")

    with pytest.raises(GraphQLSchemaLoadError, match="Unsupported GraphQL schema file extension"):
        GraphQLSchemaLoader().load(schema_path)


def test_schema_loader_maps_to_api_schema() -> None:
    api_schema = GraphQLSchemaLoader().load_as_api_schema(
        "examples/graphql/simple_users_schema.graphql",
        base_url="http://localhost:8080",
    )

    assert api_schema.base_url == "http://localhost:8080"
    assert len(api_schema.endpoints) == 3
