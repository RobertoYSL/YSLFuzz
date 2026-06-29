from yslfuzz.models import PayloadKind
from yslfuzz.payloads import MutationConfig


def test_mutation_config_defaults_are_safe() -> None:
    config = MutationConfig()

    assert PayloadKind.ATTACK not in config.enabled_payload_kinds
    assert config.include_sensitive_fields is False
    assert config.deterministic is True
    assert config.allow_invalid_enum_values is False
    assert config.allow_type_confusion is True
    assert config.allow_boundary_values is True
    assert config.allow_null_mutations is True
