from yslfuzz.config import ScanConfig


def test_config_graphql_mutation_fields_work_if_implemented() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "api_style": "GRAPHQL",
                "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
                "base_url": "http://localhost:8080",
            },
            "payloads": {
                "include_boundary_payloads": True,
                "include_invalid_payloads": True,
                "include_mutated_payloads": True,
                "include_attack_payloads": False,
                "max_mutations_per_payload": 10,
                "max_mutations_per_field": 3,
                "allow_invalid_enum_values": False,
                "mutate_sensitive_fields": False,
                "allow_extra_input_fields": True,
                "allow_missing_required_fields": True,
            },
            "execution": {
                "dry_run": True,
                "execute_mutations": False,
                "execute_attacks": False,
            },
        }
    )

    assert config.payloads.include_boundary_payloads is True
    assert config.payloads.include_invalid_payloads is True
    assert config.payloads.include_mutated_payloads is True
    assert config.payloads.allow_extra_input_fields is True
    assert config.payloads.allow_missing_required_fields is True
