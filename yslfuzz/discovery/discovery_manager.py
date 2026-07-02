"""Discovery manager for schema-source parsing."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from yslfuzz.discovery.graphql.schema_loader import GraphQLSchemaLoader
from yslfuzz.discovery.openapi_parser import OpenAPIParser
from yslfuzz.models.schema import ApiSchema


class DiscoveryManager:
    """Coordinate discovery parsers for supported schema sources."""

    def __init__(
        self,
        openapi_parser: OpenAPIParser | None = None,
        graphql_loader: GraphQLSchemaLoader | None = None,
    ) -> None:
        self._openapi_parser = openapi_parser or OpenAPIParser()
        self._graphql_loader = graphql_loader or GraphQLSchemaLoader()

    def discover_openapi(self, source: Mapping[str, Any] | str | Path) -> ApiSchema:
        return self._openapi_parser.parse(source)

    def discover_graphql(self, source: str | Path, base_url: str | None = None) -> ApiSchema:
        return self._graphql_loader.load_as_api_schema(source, base_url=base_url)
