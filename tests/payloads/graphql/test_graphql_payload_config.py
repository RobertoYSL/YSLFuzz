import pytest

from yslfuzz.payloads.graphql import GraphQLPayloadConfig


def test_graphql_payload_config_safe_defaults() -> None:
    config = GraphQLPayloadConfig()

    assert config.include_queries is True
    assert config.include_mutations is True
    assert config.include_subscriptions is False
    assert config.max_selection_depth == 2
    assert config.max_fields_per_selection == 5
    assert config.max_list_items == 1
    assert config.include_deprecated_fields is False
    assert config.deterministic is True
    assert config.generate_variables is True
    assert config.inline_literals is False


def test_graphql_payload_config_rejects_unbounded_field_count() -> None:
    with pytest.raises(ValueError, match="max_fields_per_selection"):
        GraphQLPayloadConfig(max_fields_per_selection=0)
