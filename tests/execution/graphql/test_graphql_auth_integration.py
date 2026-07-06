import httpx

from yslfuzz.auth import AuthResolver
from yslfuzz.execution import HttpExecutor
from yslfuzz.execution.graphql import GraphQLExecutor
from yslfuzz.models import AuthCredentialRef, AuthProfile, AuthType
from yslfuzz.models.base import REDACTED_VALUE
from yslfuzz.models.enums import ApiStyle, PayloadKind, Protocol
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import ScopeDefinition, Target


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id="endpoint_graphql",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body={"query": "query YSLFuzzHealth { health }", "variables": {}, "operationName": "YSLFuzzHealth"},
        generation_strategy="test",
        seed=0,
    )


def _target() -> Target:
    return Target(
        name="local",
        base_url="http://localhost:8080",
        api_style=ApiStyle.GRAPHQL,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )


def _execute_with_auth(profile: AuthProfile, environ: dict[str, str]) -> tuple[dict[str, str], object]:
    captured_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"data": {"health": "ok"}})

    auth_material = AuthResolver(environ=environ).resolve(profile)
    bundle = GraphQLExecutor(
        http_executor=HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler))),
    ).execute([_payload()], target=_target(), scan_run_id="scan_1", auth_material=auth_material)
    return captured_headers, bundle


def test_graphql_executor_applies_bearer_auth_from_profile() -> None:
    headers, bundle = _execute_with_auth(
        AuthProfile(
            name="bearer",
            auth_type=AuthType.BEARER,
            credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
        ),
        {"YSLFUZZ_TOKEN": "fake-token"},
    )

    assert headers["authorization"] == "Bearer fake-token"
    assert bundle.request_records[0].headers["Authorization"] == REDACTED_VALUE


def test_graphql_executor_applies_api_key_auth_from_profile() -> None:
    headers, bundle = _execute_with_auth(
        AuthProfile(
            name="api-key",
            auth_type=AuthType.API_KEY,
            credential_ref=AuthCredentialRef(env_var="YSLFUZZ_API_KEY"),
            header_name="X-API-Key",
        ),
        {"YSLFUZZ_API_KEY": "fake-api-key"},
    )

    assert headers["x-api-key"] == "fake-api-key"
    assert bundle.request_records[0].headers["X-API-Key"] == REDACTED_VALUE


def test_graphql_executor_applies_cookie_auth_from_profile() -> None:
    headers, bundle = _execute_with_auth(
        AuthProfile(
            name="cookie",
            auth_type=AuthType.COOKIE,
            credential_ref=AuthCredentialRef(env_var="YSLFUZZ_SESSION"),
            cookie_name="session",
        ),
        {"YSLFUZZ_SESSION": "fake-session"},
    )

    assert headers["cookie"] == "session=fake-session"
    assert bundle.request_records[0].headers["Cookie"] == REDACTED_VALUE


def test_graphql_executor_applies_custom_auth_from_profile() -> None:
    headers, bundle = _execute_with_auth(
        AuthProfile(
            name="custom",
            auth_type=AuthType.CUSTOM,
            credential_refs=[
                AuthCredentialRef(env_var="YSLFUZZ_CUSTOM", header_name="X-Custom-Auth")
            ],
        ),
        {"YSLFUZZ_CUSTOM": "fake-custom"},
    )

    assert headers["x-custom-auth"] == "fake-custom"
    assert bundle.request_records[0].headers["X-Custom-Auth"] == REDACTED_VALUE
