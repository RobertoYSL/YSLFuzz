from pydantic import SecretStr

from yslfuzz.auth import AuthInjector
from yslfuzz.models import AuthType, HttpMethod, REDACTED_VALUE, RequestRecord, ResolvedAuthMaterial


def test_auth_injector_adds_authorization_bearer_header() -> None:
    request = _request()
    resolved = ResolvedAuthMaterial(
        auth_type=AuthType.BEARER,
        headers={"Authorization": SecretStr("Bearer SENTINEL_ALPHA")},
    )

    updated = AuthInjector().apply(request, resolved)

    assert updated.headers["Authorization"] == REDACTED_VALUE
    assert "SENTINEL_ALPHA" not in updated.model_dump_json()


def test_auth_injector_adds_api_key_header() -> None:
    updated = AuthInjector().apply(
        _request(),
        ResolvedAuthMaterial(
            auth_type=AuthType.API_KEY,
            headers={"X-API-Key": SecretStr("SENTINEL_BRAVO")},
        ),
    )

    assert updated.headers["X-API-Key"] == REDACTED_VALUE


def test_auth_injector_adds_cookie_header() -> None:
    updated = AuthInjector().apply(
        _request(),
        ResolvedAuthMaterial(
            auth_type=AuthType.COOKIE,
            headers={"Cookie": SecretStr("session=SENTINEL_CHARLIE")},
        ),
    )

    assert updated.headers["Cookie"] == REDACTED_VALUE


def test_auth_injector_adds_custom_auth_header() -> None:
    updated = AuthInjector().apply(
        _request(),
        ResolvedAuthMaterial(
            auth_type=AuthType.CUSTOM,
            headers={"X-Custom-Auth": SecretStr("SENTINEL_DELTA")},
        ),
    )

    assert updated.headers["X-Custom-Auth"] == REDACTED_VALUE


def test_auth_injector_preserves_non_auth_headers() -> None:
    request = _request(headers={"Accept": "application/json"})

    updated = AuthInjector().apply(
        request,
        ResolvedAuthMaterial(
            auth_type=AuthType.BEARER,
            headers={"Authorization": SecretStr("Bearer SENTINEL_ALPHA")},
        ),
    )

    assert updated.headers["Accept"] == "application/json"


def test_auth_injector_avoids_leaking_values_in_repr_helpers() -> None:
    updated = AuthInjector().apply(
        _request(),
        ResolvedAuthMaterial(
            auth_type=AuthType.BEARER,
            headers={"Authorization": SecretStr("Bearer SENTINEL_ALPHA")},
        ),
    )

    assert "SENTINEL_ALPHA" not in repr(updated)
    assert "SENTINEL_ALPHA" not in updated.model_dump_json()


def _request(headers: dict[str, str] | None = None) -> RequestRecord:
    return RequestRecord(
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        method=HttpMethod.GET,
        url="https://api.example.test/users",
        headers=headers or {},
    )
