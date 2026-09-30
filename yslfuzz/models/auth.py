"""Authentication-related data models."""

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, SecretStr, field_serializer, field_validator, model_validator

from yslfuzz.models.base import REDACTED_VALUE, YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import AuthType, ParameterLocation


ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AuthLocation(StrEnum):
    """Supported locations for authentication material in the MVP."""

    HEADER = "HEADER"
    COOKIE = "COOKIE"


class AuthCredentialRef(YSLFuzzModel):
    """Reference to authentication material stored in an environment variable."""

    env_var: str
    source: Literal["environment"] = "environment"
    header_name: str | None = None
    cookie_name: str | None = None

    @field_validator("env_var")
    @classmethod
    def validate_env_var(cls, value: str) -> str:
        """Reject raw-looking secret values where an environment variable name is expected."""
        suspicious_fragments = ("bearer ", "basic ", "eyj", ".", "=", ":", "/", "\\")
        lowered = value.lower()
        if any(fragment in lowered for fragment in suspicious_fragments):
            raise ValueError("auth credential references must not contain raw credential values")
        if not ENV_VAR_RE.fullmatch(value):
            raise ValueError("auth credential references must be environment variable names")
        return value

    def redacted_display(self) -> dict[str, str]:
        """Return safe credential reference metadata for display/reporting."""
        return {"source": self.source, "value": REDACTED_VALUE}


class AuthScheme(YSLFuzzModel):
    auth_scheme_id: str = Field(default_factory=lambda: prefixed_id("auth_scheme"))
    auth_type: AuthType
    name: str
    location: ParameterLocation | None = None
    header_name: str | None = None
    query_param_name: str | None = None
    cookie_name: str | None = None
    description: str | None = None


class SecretReference(YSLFuzzModel):
    secret_ref_id: str = Field(default_factory=lambda: prefixed_id("secret_ref"))
    secret_type: str
    provider: str
    key_name: str
    redacted_preview: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuthProfile(YSLFuzzModel):
    """Runtime authentication profile using environment-variable credential references."""

    auth_profile_id: str = Field(default_factory=lambda: prefixed_id("auth_profile"))
    name: str = "default"
    auth_type: AuthType
    credential_ref: AuthCredentialRef | None = None
    credential_refs: list[AuthCredentialRef] = Field(default_factory=list)
    location: AuthLocation | None = None
    header_name: str | None = None
    cookie_name: str | None = None
    auth_scheme_id: str | None = None
    login_workflow_id: str | None = None
    refresh_workflow_id: str | None = None
    login_url: str | None = None
    login_body: dict[str, Any] | None = None
    login_headers: dict[str, str] = Field(default_factory=dict)
    login_user_env: str | None = None
    login_pass_env: str | None = None
    username_field: str = "email"
    password_field: str = "password"
    token_field: str = "token"
    token_type: str = "Bearer"

    @field_validator("auth_type", mode="before")
    @classmethod
    def normalize_auth_type(cls, value: object) -> object:
        """Accept CLI-style lowercase names for supported MVP auth types."""
        if isinstance(value, str):
            normalized = value.upper()
            aliases = {
                "BEARER": AuthType.BEARER,
                "API_KEY_HEADER": AuthType.API_KEY,
                "API_KEY": AuthType.API_KEY,
                "COOKIE": AuthType.COOKIE,
                "CUSTOM_HEADER": AuthType.CUSTOM,
                "CUSTOM": AuthType.CUSTOM,
            }
            return aliases.get(normalized, value)
        return value

    @field_validator("header_name", "cookie_name")
    @classmethod
    def validate_name_token(cls, value: str | None) -> str | None:
        """Validate configured header and cookie names without accepting empty values."""
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("auth header and cookie names must not be empty")
        if any(character in stripped for character in ("\r", "\n", ":")):
            raise ValueError("auth header and cookie names must be plain names")
        return stripped

    @model_validator(mode="after")
    def validate_profile(self) -> "AuthProfile":
        """Validate supported MVP authentication profile shapes."""
        if self.auth_type == AuthType.BEARER:
            if self.credential_ref is None and self.login_url is None:
                raise ValueError("bearer authentication requires an environment credential reference or login URL")
            object.__setattr__(self, "location", AuthLocation.HEADER)
            object.__setattr__(self, "header_name", "Authorization")
        elif self.auth_type == AuthType.API_KEY:
            if self.credential_ref is None and self.login_url is None:
                raise ValueError("API key header authentication requires an environment credential reference or login URL")
            object.__setattr__(self, "location", AuthLocation.HEADER)
            object.__setattr__(
                self,
                "header_name",
                self.header_name or (self.credential_ref.header_name if self.credential_ref else None) or "X-API-Key",
            )
        elif self.auth_type == AuthType.COOKIE:
            if self.credential_ref is None and self.login_url is None:
                raise ValueError("cookie authentication requires an environment credential reference or login URL")
            object.__setattr__(self, "location", AuthLocation.COOKIE)
            object.__setattr__(
                self,
                "cookie_name",
                self.cookie_name or (self.credential_ref.cookie_name if self.credential_ref else None) or "session",
            )
        elif self.auth_type == AuthType.CUSTOM:
            refs = self._custom_refs()
            if not refs:
                raise ValueError("custom header authentication requires an environment credential reference")
            if self.credential_ref is not None and self.header_name is None:
                object.__setattr__(self, "header_name", self.credential_ref.header_name)
            for ref in refs:
                header_name = ref.header_name or self.header_name
                if header_name is None:
                    raise ValueError("custom header authentication requires a header name")
            object.__setattr__(self, "location", AuthLocation.HEADER)
        else:
            raise ValueError("unsupported authentication type for Authentication Profiles MVP")
        return self

    def authentication_types(self) -> list[str]:
        """Return stable report-safe auth type names."""
        if self.auth_type == AuthType.BEARER:
            return ["bearer"]
        if self.auth_type == AuthType.API_KEY:
            return ["api_key_header"]
        if self.auth_type == AuthType.COOKIE:
            return ["cookie"]
        if self.auth_type == AuthType.CUSTOM:
            return ["custom_header"]
        return [self.auth_type.value.lower()]

    def redacted_display(self) -> dict[str, object]:
        """Return safe auth metadata without raw values or environment variable names."""
        auth_sources: list[str] = []
        if self.credential_ref is not None or self.credential_refs:
            auth_sources.append("environment")
        if self.login_url is not None:
            auth_sources.append("login")
        if not auth_sources:
            auth_sources = ["environment"]
        return {
            "authentication_enabled": True,
            "authentication_types": self.authentication_types(),
            "auth_sources": auth_sources,
            "auth_redaction_applied": True,
        }

    def _custom_refs(self) -> list[AuthCredentialRef]:
        refs = list(self.credential_refs)
        if self.credential_ref is not None:
            refs.insert(0, self.credential_ref)
        return refs


class ResolvedAuthMaterial(YSLFuzzModel):
    """Runtime-only resolved authentication headers.

    The raw values are stored as SecretStr and should only be accessed by the HTTP executor.
    """

    auth_type: AuthType
    headers: dict[str, SecretStr] = Field(default_factory=dict)
    source: str = "environment"

    @field_serializer("headers")
    def serialize_headers(self, values: dict[str, SecretStr]) -> dict[str, str]:
        """Serialize all resolved auth headers as redacted values."""
        return {name: REDACTED_VALUE for name in values}

    def headers_for_send(self) -> dict[str, str]:
        """Return raw header values for immediate HTTP execution only."""
        return {name: value.get_secret_value() for name, value in self.headers.items()}

    def redacted_headers(self) -> dict[str, str]:
        """Return header names with redacted values for request records."""
        return {name: REDACTED_VALUE for name in self.headers}

    def redacted_display(self) -> dict[str, object]:
        """Return report-safe auth metadata."""
        if self.auth_type == AuthType.BEARER:
            auth_type = "bearer"
        elif self.auth_type == AuthType.API_KEY:
            auth_type = "api_key_header"
        elif self.auth_type == AuthType.COOKIE:
            auth_type = "cookie"
        elif self.auth_type == AuthType.CUSTOM:
            auth_type = "custom_header"
        else:
            auth_type = self.auth_type.value.lower()
        return {
            "authentication_enabled": True,
            "authentication_types": [auth_type],
            "auth_sources": [self.source],
            "auth_redaction_applied": True,
        }
