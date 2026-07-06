"""Build GraphQL HTTP request records."""

from typing import Any
from urllib.parse import urljoin

from yslfuzz.execution.errors import RequestBuildError
from yslfuzz.execution.graphql.config import GraphQLExecutionConfig
from yslfuzz.execution.redaction import redact_body_value, redact_mapping_values
from yslfuzz.models.enums import HttpMethod, PayloadKind
from yslfuzz.models.execution import RequestRecord
from yslfuzz.models.payload import PayloadCandidate


class GraphQLRequestBuilder:
    """Convert a GraphQL payload candidate into a POST RequestRecord."""

    def __init__(self, config: GraphQLExecutionConfig | None = None) -> None:
        self.config = config or GraphQLExecutionConfig()

    def build(
        self,
        base_url: str,
        payload: PayloadCandidate,
        *,
        scan_run_id: str = "scan_unset",
        endpoint_id: str | None = None,
    ) -> RequestRecord:
        """Build a redacted GraphQL POST request record."""
        if payload.payload_kind != PayloadKind.VALID:
            raise RequestBuildError("GraphQL execution MVP only executes VALID payloads")
        body = self._graphql_body(payload)
        headers = dict(payload.headers)
        headers.setdefault("Content-Type", self.config.content_type)
        headers.setdefault("Accept", "application/json")
        return RequestRecord(
            scan_run_id=scan_run_id,
            endpoint_id=endpoint_id or payload.endpoint_id,
            payload_id=payload.payload_id,
            method=HttpMethod.POST,
            url=self._url(base_url),
            headers=redact_mapping_values(headers),
            cookies=redact_mapping_values(payload.cookies),
            body=redact_body_value(body) if self.config.redact_request_body else body,
            content_type=self.config.content_type,
            metadata={
                "api_style": "graphql",
                "graphql_operation_name": payload.metadata.get("graphql_operation_name"),
                "graphql_operation_type": payload.metadata.get("graphql_operation_type"),
                "graphql_endpoint_path": self.config.graphql_endpoint_path,
            },
        )

    def _graphql_body(self, payload: PayloadCandidate) -> dict[str, Any]:
        if not isinstance(payload.body, dict):
            raise RequestBuildError("GraphQL payload body must be an object")
        query = payload.body.get("query")
        if not isinstance(query, str) or not query.strip():
            raise RequestBuildError("GraphQL payload body requires query")
        body: dict[str, Any] = {"query": query}
        if self.config.include_variables:
            variables = payload.body.get("variables", {})
            if not isinstance(variables, dict):
                raise RequestBuildError("GraphQL payload variables must be an object")
            body["variables"] = variables
        if self.config.include_operation_name:
            operation_name = payload.body.get("operationName")
            if operation_name is not None and not isinstance(operation_name, str):
                raise RequestBuildError("GraphQL payload operationName must be a string")
            if operation_name:
                body["operationName"] = operation_name
        return body

    def _url(self, base_url: str) -> str:
        return urljoin(base_url, self.config.graphql_endpoint_path)
