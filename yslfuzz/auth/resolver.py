"""Resolve authentication profiles from runtime environment variables."""

import os
from collections.abc import Mapping

from pydantic import SecretStr

from yslfuzz.models.auth import AuthCredentialRef, AuthProfile, ResolvedAuthMaterial
from yslfuzz.models.enums import AuthType


class AuthResolutionError(ValueError):
    """Raised when an auth profile cannot be resolved safely."""


class AuthResolver:
    """Resolve authentication material from environment variables at runtime."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def resolve(self, profile: AuthProfile) -> ResolvedAuthMaterial:
        """Resolve an auth profile into runtime HTTP header material."""
        if profile.auth_type == AuthType.BEARER:
            credential = self._read_required(profile.credential_ref)
            return ResolvedAuthMaterial(
                auth_type=AuthType.BEARER,
                headers={"Authorization": SecretStr(f"Bearer {credential}")},
            )
        if profile.auth_type == AuthType.API_KEY:
            credential = self._read_required(profile.credential_ref)
            header_name = profile.header_name or "X-API-Key"
            return ResolvedAuthMaterial(
                auth_type=AuthType.API_KEY,
                headers={header_name: SecretStr(credential)},
            )
        if profile.auth_type == AuthType.COOKIE:
            credential = self._read_required(profile.credential_ref)
            cookie_name = profile.cookie_name or "session"
            return ResolvedAuthMaterial(
                auth_type=AuthType.COOKIE,
                headers={"Cookie": SecretStr(f"{cookie_name}={credential}")},
            )
        if profile.auth_type == AuthType.CUSTOM:
            headers: dict[str, SecretStr] = {}
            for ref in self._custom_refs(profile):
                custom_header_name = ref.header_name or profile.header_name
                if custom_header_name is None:
                    raise AuthResolutionError("Custom authentication header name is not configured")
                headers[custom_header_name] = SecretStr(self._read_required(ref))
            return ResolvedAuthMaterial(auth_type=AuthType.CUSTOM, headers=headers)
        raise AuthResolutionError("Unsupported authentication type")

    def _read_required(self, credential_ref: AuthCredentialRef | None) -> str:
        if credential_ref is None:
            raise AuthResolutionError("Authentication credential reference is not configured")
        value = self._environ.get(credential_ref.env_var)
        if value is None or value == "":
            raise AuthResolutionError("Required authentication environment variable is not set")
        return value

    def _custom_refs(self, profile: AuthProfile) -> list[AuthCredentialRef]:
        refs = list(profile.credential_refs)
        if profile.credential_ref is not None:
            refs.insert(0, profile.credential_ref)
        return refs
