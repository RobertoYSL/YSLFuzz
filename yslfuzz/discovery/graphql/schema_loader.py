"""Local GraphQL schema loader."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path

from yslfuzz.discovery.graphql.introspection_parser import GraphQLIntrospectionParser
from yslfuzz.discovery.graphql.mapper import GraphQLToApiSchemaMapper
from yslfuzz.discovery.graphql.models import GraphQLSchema
from yslfuzz.discovery.graphql.sdl_parser import GraphQLSDLParser
from yslfuzz.models.schema import ApiSchema


class GraphQLSchemaLoadError(ValueError):
    """Raised when a local GraphQL schema source cannot be loaded."""


class GraphQLSchemaLoader:
    """Load local GraphQL SDL or introspection JSON files."""

    def __init__(
        self,
        sdl_parser: GraphQLSDLParser | None = None,
        introspection_parser: GraphQLIntrospectionParser | None = None,
        mapper: GraphQLToApiSchemaMapper | None = None,
    ) -> None:
        self._sdl_parser = sdl_parser or GraphQLSDLParser()
        self._introspection_parser = introspection_parser or GraphQLIntrospectionParser()
        self._mapper = mapper or GraphQLToApiSchemaMapper()

    def load(self, path: str | Path) -> GraphQLSchema:
        """Load a local GraphQL schema file into GraphQLSchema."""
        source = Path(path)
        if not source.exists():
            raise GraphQLSchemaLoadError(f"GraphQL schema file does not exist: {source}")
        if not source.is_file():
            raise GraphQLSchemaLoadError(f"GraphQL schema source is not a file: {source}")

        suffix = source.suffix.lower()
        raw = source.read_text(encoding="utf-8")
        if suffix in {".graphql", ".gql"}:
            schema = self._sdl_parser.parse(raw)
        elif suffix == ".json" or self._looks_like_json(raw):
            schema = self._load_json(raw, source)
        else:
            raise GraphQLSchemaLoadError(
                "Unsupported GraphQL schema file extension "
                f"'{source.suffix}'. Use .graphql, .gql, or .json"
            )
        schema.source_location = str(source)
        return schema

    def load_as_api_schema(self, path: str | Path, base_url: str | None = None) -> ApiSchema:
        """Load and map a local GraphQL schema file into ApiSchema."""
        return self._mapper.map(self.load(path), base_url=base_url)

    def _load_json(self, raw: str, source: Path) -> GraphQLSchema:
        try:
            data = json.loads(raw)
        except JSONDecodeError as exc:
            raise GraphQLSchemaLoadError(f"Could not parse GraphQL introspection JSON {source}: {exc}") from exc
        if not isinstance(data, dict):
            raise GraphQLSchemaLoadError("GraphQL introspection JSON root must be an object")
        return self._introspection_parser.parse(data)

    def _looks_like_json(self, raw: str) -> bool:
        stripped = raw.lstrip()
        return stripped.startswith("{") or stripped.startswith("[")
