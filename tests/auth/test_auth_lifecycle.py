"""Unit tests for authentication lifecycle management."""

import httpx
import pytest

from yslfuzz.auth.lifecycle import (
    AuthLifecycleError,
    AuthLifecycleManager,
    DynamicAuthConfig,
)
from yslfuzz.auth.resolver import AuthResolver
from yslfuzz.models.auth import AuthProfile
from yslfuzz.models.enums import AuthType


def test_auth_lifecycle_extracts_bearer_token_from_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth/login"
        assert request.method == "POST"
        return httpx.Response(200, json={"token": "mocked-jwt-token", "type": "Bearer"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    manager = AuthLifecycleManager(client=client)

    config = DynamicAuthConfig(
        login_url="http://testserver/auth/login",
        body={"email": "alice@example.test", "password": "secretpassword"},
    )
    resolved = manager.authenticate(config)

    assert resolved.auth_type == AuthType.BEARER
    assert resolved.source == "login"
    assert resolved.headers_for_send()["Authorization"] == "Bearer mocked-jwt-token"
    assert resolved.redacted_headers()["Authorization"] == "[REDACTED]"


def test_auth_lifecycle_with_credentials_from_environment() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        import json

        data = json.loads(request.content.decode())
        assert data["email"] == "envuser@test.org"
        assert data["password"] == "envpassword123"
        return httpx.Response(200, json={"access_token": "token-from-env-creds"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    environ = {
        "TEST_USER": "envuser@test.org",
        "TEST_PASS": "envpassword123",
    }
    manager = AuthLifecycleManager(client=client, environ=environ)

    config = DynamicAuthConfig(
        login_url="http://testserver/api/v1/login",
        username_env="TEST_USER",
        password_env="TEST_PASS",
        token_field="access_token",
    )
    resolved = manager.authenticate(config)

    assert resolved.headers_for_send()["Authorization"] == "Bearer token-from-env-creds"


def test_auth_lifecycle_extracts_nested_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"jwt": "nested-token-value"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    manager = AuthLifecycleManager(client=client)

    config = DynamicAuthConfig(
        login_url="http://testserver/login",
        token_field="data.jwt",
    )
    resolved = manager.authenticate(config)

    assert resolved.headers_for_send()["Authorization"] == "Bearer nested-token-value"


def test_auth_lifecycle_handles_cookies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, content=b"logged in")
        response.headers["set-cookie"] = "session_id=mock-session-cookie; Path=/"
        return response

    client = httpx.Client(transport=httpx.MockTransport(handler))
    manager = AuthLifecycleManager(client=client)

    config = DynamicAuthConfig(
        login_url="http://testserver/login",
        token_field="nonexistent",
    )
    resolved = manager.authenticate(config)

    assert resolved.auth_type == AuthType.COOKIE
    assert "session_id=mock-session-cookie" in resolved.headers_for_send()["Cookie"]


def test_auth_lifecycle_raises_on_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    manager = AuthLifecycleManager(client=client)

    config = DynamicAuthConfig(login_url="http://testserver/login")
    with pytest.raises(AuthLifecycleError, match="returned error status 401"):
        manager.authenticate(config)


def test_auth_resolver_delegates_to_dynamic_lifecycle() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": "dynamic-resolved-token"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resolver = AuthResolver(client=client)

    profile = AuthProfile(
        name="dynamic_test",
        auth_type=AuthType.BEARER,
        login_url="http://testserver/auth/login",
        login_body={"email": "test@test.local"},
    )
    resolved = resolver.resolve(profile)

    assert resolved.headers_for_send()["Authorization"] == "Bearer dynamic-resolved-token"
    assert resolved.source == "login"
