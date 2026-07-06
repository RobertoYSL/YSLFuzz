import pytest

from yslfuzz.analysis.graphql import GraphQLAnalysisConfig


def test_graphql_analysis_config_safe_defaults() -> None:
    config = GraphQLAnalysisConfig()

    assert config.enable_graphql_error_disclosure is True
    assert config.enable_graphql_authorization_consistency is True
    assert config.max_error_messages_to_analyze == 10
    assert config.max_evidence_preview_chars == 300


def test_graphql_analysis_config_rejects_unbounded_limits() -> None:
    with pytest.raises(ValueError):
        GraphQLAnalysisConfig(max_evidence_preview_chars=0)

