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


def test_schema_loader_loads_from_url_with_post_introspection(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    fake_introspection = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "hello",
                                "type": {"kind": "SCALAR", "name": "String"},
                                "args": [],
                            }
                        ],
                    }
                ],
            }
        }
    }

    class MockResponse:
        status_code = 200

        def json(self) -> dict:
            return fake_introspection

        def raise_for_status(self) -> None:
            pass

    class MockClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self) -> "MockClient":
            return self

        def __exit__(self, *args) -> None:
            pass

        def post(self, url: str, **kwargs) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr(httpx, "Client", MockClient)

    schema = GraphQLSchemaLoader().load("http://api.example.com/graphql")
    assert schema.source_format == "introspection_json"
    assert schema.operation_counts()["query_count"] == 1
    assert schema.source_location == "http://api.example.com/graphql"

    api_schema = GraphQLSchemaLoader().load_as_api_schema("http://api.example.com/graphql")
    assert api_schema.base_url == "http://api.example.com"


def test_schema_loader_loads_from_url_fallback_sdl(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    class MockResponse:
        status_code = 200
        text = "type Query { ping: String }"

        def json(self) -> dict:
            raise ValueError("not json")

        def raise_for_status(self) -> None:
            pass

    class MockClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self) -> "MockClient":
            return self

        def __exit__(self, *args) -> None:
            pass

        def post(self, url: str, **kwargs) -> MockResponse:
            res = MockResponse()
            res.status_code = 405
            return res

        def get(self, url: str, **kwargs) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr(httpx, "Client", MockClient)

    schema = GraphQLSchemaLoader().load("http://api.example.com/schema.graphql")
    assert schema.source_format == "sdl"
    assert schema.operation_counts()["query_count"] == 1


def test_schema_loader_url_failure_raises_load_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    class FailingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self) -> "FailingClient":
            return self

        def __exit__(self, *args) -> None:
            pass

        def post(self, url: str, **kwargs) -> None:
            raise httpx.ConnectError("Connection refused")

        def get(self, url: str, **kwargs) -> None:
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "Client", FailingClient)

    with pytest.raises(GraphQLSchemaLoadError, match="Could not load GraphQL schema from URL"):
        GraphQLSchemaLoader().load("http://localhost:9999/graphql")

