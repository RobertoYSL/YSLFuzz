import pytest
from pydantic import ValidationError

from yslfuzz.models import AuthCredentialRef, AuthProfile, AuthType


def test_auth_profile_validates_bearer_env_configuration() -> None:
    profile = AuthProfile(
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
    )

    assert profile.header_name == "Authorization"
    assert profile.authentication_types() == ["bearer"]


def test_auth_profile_validates_api_key_header_configuration() -> None:
    profile = AuthProfile(
        auth_type="api_key_header",
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_API_KEY"),
        header_name="X-API-Key",
    )

    assert profile.auth_type == AuthType.API_KEY
    assert profile.header_name == "X-API-Key"


def test_auth_profile_validates_cookie_configuration() -> None:
    profile = AuthProfile(
        auth_type=AuthType.COOKIE,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_SESSION"),
        cookie_name="session",
    )

    assert profile.cookie_name == "session"
    assert profile.authentication_types() == ["cookie"]


def test_auth_profile_validates_custom_header_configuration() -> None:
    profile = AuthProfile(
        auth_type="custom_header",
        credential_refs=[
            AuthCredentialRef(env_var="YSLFUZZ_CUSTOM_AUTH", header_name="X-Custom-Auth")
        ],
    )

    assert profile.auth_type == AuthType.CUSTOM
    assert profile.authentication_types() == ["custom_header"]


@pytest.mark.parametrize(
    "raw_value",
    ["Bearer raw-token", "eyJhbGciOi.fake.jwt", "token=value", "raw/token"],
)
def test_auth_profile_rejects_raw_secret_values_where_env_var_names_are_expected(
    raw_value: str,
) -> None:
    with pytest.raises(ValidationError):
        AuthCredentialRef(env_var=raw_value)


def test_auth_profile_redacted_display_omits_env_var_names() -> None:
    profile = AuthProfile(
        auth_type=AuthType.BEARER,
        credential_ref=AuthCredentialRef(env_var="YSLFUZZ_TOKEN"),
    )

    display = profile.redacted_display()

    assert display["authentication_enabled"] is True
    assert display["authentication_types"] == ["bearer"]
    assert display["auth_sources"] == ["environment"]
    assert "YSLFUZZ_TOKEN" not in str(display)
