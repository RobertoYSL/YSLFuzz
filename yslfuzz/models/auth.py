"""Authentication-related data models."""

from datetime import datetime

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import AuthType, ParameterLocation


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
    auth_profile_id: str = Field(default_factory=lambda: prefixed_id("auth_profile"))
    name: str
    auth_scheme_id: str
    credential_ref: SecretReference
    login_workflow_id: str | None = None
    refresh_workflow_id: str | None = None
