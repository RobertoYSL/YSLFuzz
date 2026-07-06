import pytest

from yslfuzz.execution.graphql import GraphQLExecutionConfig


def test_graphql_execution_config_safe_defaults() -> None:
    config = GraphQLExecutionConfig()

    assert config.graphql_endpoint_path == "/graphql"
    assert config.method == "POST"
    assert config.content_type == "application/json"
    assert config.execute_graphql is True
    assert config.dry_run is False
    assert config.reject_get_execution is True
    assert config.redact_request_body is True


def test_graphql_execution_config_rejects_get_execution_if_configured() -> None:
    with pytest.raises(ValueError, match="GET-based GraphQL execution"):
        GraphQLExecutionConfig(method="GET")


def test_graphql_execution_config_rejects_non_json_content_type() -> None:
    with pytest.raises(ValueError, match="application/json"):
        GraphQLExecutionConfig(content_type="application/graphql")
