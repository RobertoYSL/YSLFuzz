"""Configuration for safe GraphQL HTTP execution."""

from pydantic import model_validator

from yslfuzz.models.base import YSLFuzzModel


class GraphQLExecutionConfig(YSLFuzzModel):
    """Safe defaults for GraphQL execution through the shared HTTP executor."""

    graphql_endpoint_path: str = "/graphql"
    method: str = "POST"
    content_type: str = "application/json"
    execute_graphql: bool = True
    dry_run: bool = False
    timeout: float | None = None
    max_graphql_requests: int | None = None
    include_operation_name: bool = True
    include_variables: bool = True
    reject_get_execution: bool = True
    redact_request_body: bool = True

    @model_validator(mode="after")
    def validate_execution_config(self) -> "GraphQLExecutionConfig":
        """Reject unsafe GraphQL execution modes."""
        normalized_method = self.method.upper()
        object.__setattr__(self, "method", normalized_method)
        if self.reject_get_execution and normalized_method == "GET":
            raise ValueError("GET-based GraphQL execution is not supported in the MVP")
        if normalized_method != "POST":
            raise ValueError("GraphQL execution MVP supports POST only")
        if self.content_type.lower() != "application/json":
            raise ValueError("GraphQL execution MVP supports application/json only")
        if not self.graphql_endpoint_path.startswith("/"):
            raise ValueError("graphql_endpoint_path must start with '/'")
        if "://" in self.graphql_endpoint_path:
            raise ValueError("graphql_endpoint_path must be a local path, not a URL")
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if self.max_graphql_requests is not None and self.max_graphql_requests < 0:
            raise ValueError("max_graphql_requests must be non-negative")
        return self
