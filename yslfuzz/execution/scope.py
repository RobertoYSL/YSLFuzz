"""Scope validation and destructive method guards."""

from urllib.parse import urlparse

from yslfuzz.execution.errors import (
    DestructiveMethodBlockedError,
    InvalidRequestURLError,
    ScopeViolationError,
)
from yslfuzz.models.enums import HttpMethod
from yslfuzz.models.execution import RequestRecord
from yslfuzz.models.project import ScopeDefinition


DESTRUCTIVE_METHODS = {HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH}


class ScopeValidator:
    """Validate requests against host, path, method, and destructive-method scope rules."""

    def validate(
        self,
        request_record: RequestRecord,
        scope_definition: ScopeDefinition,
    ) -> None:
        """Raise when the request must not be executed."""
        parsed_url = urlparse(request_record.url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise InvalidRequestURLError(f"Invalid request URL: {request_record.url}")

        self._validate_method(request_record.method, scope_definition)
        self._validate_host(parsed_url.hostname, parsed_url.netloc, scope_definition)
        self._validate_path(parsed_url.path or "/", scope_definition)

    def _validate_method(self, method: HttpMethod, scope_definition: ScopeDefinition) -> None:
        if method in DESTRUCTIVE_METHODS and not scope_definition.allow_destructive_methods:
            raise DestructiveMethodBlockedError(f"{method.value} is blocked by safe defaults")
        if method not in scope_definition.allowed_methods:
            raise ScopeViolationError(f"{method.value} is not in allowed_methods")

    def _validate_host(
        self,
        hostname: str | None,
        netloc: str,
        scope_definition: ScopeDefinition,
    ) -> None:
        if hostname is None:
            raise InvalidRequestURLError("Request URL has no host")
        allowed = {host.lower() for host in scope_definition.allowed_hosts}
        if hostname.lower() not in allowed and netloc.lower() not in allowed:
            raise ScopeViolationError(f"Host '{netloc}' is outside the allowed scope")

    def _validate_path(self, path: str, scope_definition: ScopeDefinition) -> None:
        if any(self._path_matches(path, blocked) for blocked in scope_definition.blocked_paths):
            raise ScopeViolationError(f"Path '{path}' is blocked by scope")
        if not any(self._path_matches(path, allowed) for allowed in scope_definition.allowed_paths):
            raise ScopeViolationError(f"Path '{path}' is outside allowed paths")

    def _path_matches(self, path: str, configured_path: str) -> bool:
        normalized = configured_path if configured_path.startswith("/") else f"/{configured_path}"
        return path == normalized or path.startswith(normalized.rstrip("/") + "/")
