import pytest

from yslfuzz.payloads.graphql import GraphQLMutationConfig


def test_graphql_mutation_config_safe_defaults() -> None:
    config = GraphQLMutationConfig()

    assert config.include_boundary_payloads is False
    assert config.include_invalid_payloads is False
    assert config.include_mutated_payloads is False
    assert config.include_attack_payloads is False
    assert config.include_sensitive_fields is False
    assert config.allow_invalid_enum_values is False
    assert config.allow_type_confusion is True
    assert config.allow_introspection_probe is False
    assert config.deterministic is True


def test_graphql_mutation_config_rejects_negative_limits() -> None:
    with pytest.raises(ValueError, match="max_mutations_per_payload"):
        GraphQLMutationConfig(max_mutations_per_payload=-1)
