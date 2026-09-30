"""Authentication lifecycle management for dynamic login flows."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin

import httpx
from pydantic import Field, SecretStr, field_serializer

from yslfuzz.models.auth import ResolvedAuthMaterial
from yslfuzz.models.base import REDACTED_VALUE, YSLFuzzModel
from yslfuzz.models.enums import AuthType


class AuthLifecycleError(ValueError):
    """Raised when dynamic authentication fails."""


class DynamicAuthConfig(YSLFuzzModel):
    """Configuration for dynamic login-based authentication."""

    login_url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=lambda: {"Content-Type": "application/json"})
    body: dict[str, Any] = Field(default_factory=dict)
    token_field: str = "token"
    token_type: str = "Bearer"
    username_env: str | None = None
    password_env: str | None = None
    username_field: str = "email"
    password_field: str = "password"

    @field_serializer("body")
    def serialize_body(self, value: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive fields in login body."""
        return {
            key: (
                REDACTED_VALUE
                if any(sub in key.lower() for sub in ("pass", "secret", "token", "key", "cred"))
                else val
            )
            for key, val in value.items()
        }


class AuthLifecycleManager:
    """Manages pre-flight authentication and dynamic token retrieval."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._client = client
        self._environ = environ if environ is not None else os.environ

    def authenticate(
        self,
        config: DynamicAuthConfig,
        base_url: str | None = None,
    ) -> ResolvedAuthMaterial:
        """Execute pre-flight login request and return resolved auth material."""
        url = self._resolve_url(config.login_url, base_url)
        body = self._prepare_body(config)
        headers = dict(config.headers)

        client = self._client or httpx.Client(timeout=15.0)
        try:
            response = client.request(
                method=config.method.upper(),
                url=url,
                json=body if body else None,
                headers=headers,
            )
        except Exception as exc:
            raise AuthLifecycleError(f"Login request to '{url}' failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            raise AuthLifecycleError(
                f"Login request to '{url}' returned error status {response.status_code}"
            )

        token = self._extract_token(response, config.token_field)
        if token:
            prefix = f"{config.token_type} ".strip()
            auth_header_value = f"{prefix} {token}".strip()
            return ResolvedAuthMaterial(
                auth_type=AuthType.BEARER,
                headers={"Authorization": SecretStr(auth_header_value)},
                source="login",
            )

        # Check for cookies if no JSON token was found
        cookies = response.cookies
        if cookies:
            cookie_header = "; ".join(f"{key}={val}" for key, val in cookies.items())
            return ResolvedAuthMaterial(
                auth_type=AuthType.COOKIE,
                headers={"Cookie": SecretStr(cookie_header)},
                source="login",
            )

        raise AuthLifecycleError(
            f"Could not extract token using field '{config.token_field}' from login response at '{url}'"
        )

    def _resolve_url(self, login_url: str, base_url: str | None) -> str:
        if login_url.startswith(("http://", "https://")):
            return login_url
        if base_url:
            return urljoin(base_url.rstrip("/") + "/", login_url.lstrip("/"))
        return login_url

    def _prepare_body(self, config: DynamicAuthConfig) -> dict[str, Any]:
        body = dict(config.body)
        if config.username_env:
            username = self._environ.get(config.username_env)
            if username:
                body[config.username_field] = username
        if config.password_env:
            password = self._environ.get(config.password_env)
            if password:
                body[config.password_field] = password
        return body

    def _extract_token(self, response: httpx.Response, token_field: str) -> str | None:
        try:
            data = response.json()
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        if "." in token_field:
            curr: Any = data
            for part in token_field.split("."):
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                else:
                    curr = None
                    break
            if isinstance(curr, str):
                return str(curr)

        val = data.get(token_field)
        if isinstance(val, str):
            return str(val)

        # Common fallbacks if not found directly
        for candidate in ("token", "access_token", "jwt", "accessToken", "id_token"):
            cand_val = data.get(candidate)
            if isinstance(cand_val, str):
                return str(cand_val)

        return None
