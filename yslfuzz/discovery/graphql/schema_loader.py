"""Local GraphQL schema loader."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from urllib.parse import urlparse

import httpx

from yslfuzz.discovery.graphql.introspection_parser import GraphQLIntrospectionParser
from yslfuzz.discovery.graphql.mapper import GraphQLToApiSchemaMapper
from yslfuzz.discovery.graphql.models import GraphQLSchema
from yslfuzz.discovery.graphql.sdl_parser import GraphQLSDLParser
from yslfuzz.models.schema import ApiSchema

STANDARD_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { ...TypeRef }
        defaultValue
      }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { ...TypeRef }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


class GraphQLSchemaLoadError(ValueError):
    """Raised when a local or remote GraphQL schema source cannot be loaded."""


class GraphQLSchemaLoader:
    """Load local GraphQL SDL or introspection JSON files or remote endpoints."""

    def __init__(
        self,
        sdl_parser: GraphQLSDLParser | None = None,
        introspection_parser: GraphQLIntrospectionParser | None = None,
        mapper: GraphQLToApiSchemaMapper | None = None,
    ) -> None:
        self._sdl_parser = sdl_parser or GraphQLSDLParser()
        self._introspection_parser = introspection_parser or GraphQLIntrospectionParser()
        self._mapper = mapper or GraphQLToApiSchemaMapper()

    def load(self, path_or_url: str | Path) -> GraphQLSchema:
        """Load a local GraphQL schema file or remote URL into GraphQLSchema."""
        if isinstance(path_or_url, str) and path_or_url.startswith(("http://", "https://")):
            return self.load_from_url(path_or_url)

        source = Path(path_or_url)
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

    def load_from_url(self, url: str, timeout: float = 10.0) -> GraphQLSchema:
        """Fetch and parse schema from a remote GraphQL endpoint or schema URL."""
        try:
            with httpx.Client(timeout=timeout) as client:
                try:
                    resp = client.post(
                        url,
                        json={"query": STANDARD_INTROSPECTION_QUERY},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict) and (
                            "__schema" in data
                            or ("data" in data and isinstance(data["data"], dict) and "__schema" in data["data"])
                        ):
                            schema = self._introspection_parser.parse(data)
                            schema.source_location = url
                            return schema
                except Exception:
                    pass

                # If POST introspection query didn't work, try GET (e.g. static hosted schema file)
                resp = client.get(url)
                resp.raise_for_status()
                raw = resp.text
                if self._looks_like_json(raw):
                    try:
                        data = resp.json()
                        schema = self._introspection_parser.parse(data)
                        schema.source_location = url
                        return schema
                    except Exception as exc:
                        raise GraphQLSchemaLoadError(f"Failed to parse JSON schema from {url}: {exc}") from exc
                else:
                    schema = self._sdl_parser.parse(raw)
                    schema.source_location = url
                    return schema
        except GraphQLSchemaLoadError:
            raise
        except Exception as exc:
            raise GraphQLSchemaLoadError(f"Could not load GraphQL schema from URL {url}: {exc}") from exc

    def load_as_api_schema(self, path_or_url: str | Path, base_url: str | None = None) -> ApiSchema:
        """Load and map a local or remote GraphQL schema into ApiSchema."""
        if base_url is None and isinstance(path_or_url, str) and path_or_url.startswith(("http://", "https://")):
            parsed = urlparse(path_or_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        return self._mapper.map(self.load(path_or_url), base_url=base_url)

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
