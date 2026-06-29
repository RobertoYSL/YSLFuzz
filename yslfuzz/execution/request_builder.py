"""Build persisted request records from endpoint and payload models."""

from typing import Any
from urllib.parse import quote, urljoin

from yslfuzz.execution.errors import RequestBuildError
from yslfuzz.execution.redaction import redact_body_value, redact_mapping_values
from yslfuzz.execution.session import merge_session_cookies, merge_session_headers
from yslfuzz.models.enums import ApiStyle, ParameterLocation
from yslfuzz.models.execution import RequestRecord, SessionState
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import Target
from yslfuzz.models.schema import Endpoint


class RequestBuilder:
    """Convert a REST endpoint and payload candidate into a RequestRecord."""

    def build(
        self,
        endpoint: Endpoint,
        payload: PayloadCandidate,
        target: Target,
        session_state: SessionState | None = None,
        scan_run_id: str = "scan_unset",
    ) -> RequestRecord:
        """Build a redacted request record ready for scoped execution."""
        if endpoint.api_style != ApiStyle.REST or endpoint.method is None or endpoint.path is None:
            raise RequestBuildError("RequestBuilder MVP supports REST endpoints only")
        if payload.endpoint_id != endpoint.endpoint_id:
            raise RequestBuildError("Payload endpoint_id does not match endpoint")

        path_params = self._parameters_by_location(payload, ParameterLocation.PATH)
        query_params = self._parameters_by_location(payload, ParameterLocation.QUERY)
        header_params = self._parameters_by_location(payload, ParameterLocation.HEADER)
        cookie_params = self._parameters_by_location(payload, ParameterLocation.COOKIE)

        headers = merge_session_headers({**payload.headers, **header_params}, session_state)
        cookies = merge_session_cookies({**payload.cookies, **cookie_params}, session_state)

        if payload.content_type:
            headers.setdefault("Content-Type", payload.content_type)

        redacted_path_params = redact_mapping_values(path_params)
        return RequestRecord(
            scan_run_id=scan_run_id,
            endpoint_id=endpoint.endpoint_id,
            payload_id=payload.payload_id,
            method=endpoint.method,
            url=self._build_url(target.base_url, endpoint.path, redacted_path_params),
            headers=redact_mapping_values(headers),
            query_params=redact_mapping_values(query_params),
            path_params=redacted_path_params,
            cookies=redact_mapping_values(cookies),
            body=redact_body_value(payload.body),
            content_type=payload.content_type,
        )

    def _parameters_by_location(
        self,
        payload: PayloadCandidate,
        location: ParameterLocation,
    ) -> dict[str, Any]:
        return {
            parameter.name: parameter.value
            for parameter in payload.parameters
            if parameter.location == location
        }

    def _build_url(self, base_url: str, endpoint_path: str, path_params: dict[str, Any]) -> str:
        rendered_path = endpoint_path
        for name, value in path_params.items():
            rendered_path = rendered_path.replace(
                "{" + name + "}",
                quote(str(value), safe=""),
            )
        if "{" in rendered_path or "}" in rendered_path:
            raise RequestBuildError(f"Missing path parameter for endpoint path: {endpoint_path}")

        normalized_base = base_url if base_url.endswith("/") else f"{base_url}/"
        normalized_path = rendered_path.lstrip("/")
        return urljoin(normalized_base, normalized_path)
