"""Discovery manager for schema-source parsing."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from yslfuzz.discovery.openapi_parser import OpenAPIParser
from yslfuzz.models.schema import ApiSchema


class DiscoveryManager:
    """Coordinate discovery parsers for supported schema sources."""

    def __init__(self, openapi_parser: OpenAPIParser | None = None) -> None:
        self._openapi_parser = openapi_parser or OpenAPIParser()

    def discover_openapi(self, source: Mapping[str, Any] | str | Path) -> ApiSchema:
        return self._openapi_parser.parse(source)
