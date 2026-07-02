import pytest

from yslfuzz.auth import AuthResolutionError, AuthResolver
from yslfuzz.models import AuthCredentialRef, AuthProfile, AuthType


def test_auth_resolver_reads_bearer_token_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_ALPHA")
    profile = AuthProfile(
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
    )

    resolved = AuthResolver().resolve(profile)

    assert resolved.headers_for_send()["Authorization"] == "Bearer SENTINEL_ALPHA"


def test_auth_resolver_fails_clearly_when_bearer_env_var_is_missing() -> None:
    profile = AuthProfile(
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
    )

    with pytest.raises(AuthResolutionError, match="environment variable is not set") as exc_info:
        AuthResolver(environ={}).resolve(profile)

    assert "YSLFUZZ_TOKEN" not in str(exc_info.value)


def test_auth_resolver_exception_does_not_expose_secret_values() -> None:
    profile = AuthProfile(
        auth_type=AuthType.API_KEY,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_API_KEY"),
    )

    with pytest.raises(AuthResolutionError) as exc_info:
        AuthResolver(environ={}).resolve(profile)

    assert "SENTINEL_ALPHA" not in str(exc_info.value)
    assert "YSLFUZZ_API_KEY" not in str(exc_info.value)


def test_auth_resolver_redacted_display_never_shows_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_ALPHA")
    profile = AuthProfile(
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
    )

    resolved = AuthResolver().resolve(profile)

    assert "SENTINEL_ALPHA" not in repr(resolved)
    assert "SENTINEL_ALPHA" not in resolved.model_dump_json()
    assert resolved.redacted_display()["authentication_types"] == ["bearer"]
