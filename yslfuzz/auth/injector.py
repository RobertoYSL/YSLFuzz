"""Inject resolved authentication markers into request records."""

from yslfuzz.models.auth import ResolvedAuthMaterial
from yslfuzz.models.base import REDACTED_VALUE
from yslfuzz.models.execution import RequestRecord


class AuthInjector:
    """Apply redacted authentication headers to a request record."""

    def apply(
        self,
        request: RequestRecord,
        resolved_auth: ResolvedAuthMaterial | None,
    ) -> RequestRecord:
        """Return a request record with redacted auth markers applied."""
        if resolved_auth is None:
            return request

        updated = request.model_copy(deep=True)
        headers = dict(updated.headers)
        for name in resolved_auth.headers:
            existing_name = self._existing_header_name(headers, name)
            headers[existing_name or name] = REDACTED_VALUE
        updated.headers = headers
        return updated

    def _existing_header_name(self, headers: dict[str, object], name: str) -> str | None:
        for existing_name in headers:
            if existing_name.lower() == name.lower():
                return existing_name
        return None
