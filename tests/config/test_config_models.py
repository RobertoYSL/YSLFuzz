import pytest
from pydantic import ValidationError

from yslfuzz.config import ScanConfig


def test_scan_config_validates_minimal_target_openapi_base_url_configuration() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "openapi_path": "examples/openapi/simple_users_api.yaml",
                "base_url": "http://localhost:8000",
            }
        }
    )

    assert config.target.openapi_path == "examples/openapi/simple_users_api.yaml"
    assert config.target.base_url == "http://localhost:8000"


def test_scan_config_safe_defaults_are_applied() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "openapi_path": "examples/openapi/simple_users_api.yaml",
                "base_url": "http://localhost:8000",
            }
        }
    )

    assert config.execution.dry_run is True
    assert config.execution.allow_destructive is False
    assert config.execution.execute_attacks is False
    assert config.execution.execute_mutations is False
    assert config.payloads.include_attack_payloads is False
    assert config.payloads.include_mutated_payloads is False
    assert config.payloads.include_invalid_payloads is False
    assert config.payloads.include_boundary_payloads is False
    assert config.payloads.mutate_sensitive_fields is False
    assert config.safety.redact_secrets is True


def test_config_validation_rejects_raw_looking_bearer_token() -> None:
    with pytest.raises(ValidationError, match="raw credential values"):
        ScanConfig.model_validate(
            {
                "target": {
                    "openapi_path": "examples/openapi/simple_users_api.yaml",
                    "base_url": "http://localhost:8000",
                },
                "auth": {"bearer_env": "eyJhbGciOi.raw.jwt"},
            }
        )


def test_config_validation_accepts_bearer_env_var_name() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "openapi_path": "examples/openapi/simple_users_api.yaml",
                "base_url": "http://localhost:8000",
            },
            "auth": {"bearer_env": "YSLFUZZ_TOKEN"},
        }
    )

    assert config.auth.bearer_env == "YSLFUZZ_TOKEN"


def test_config_validation_rejects_query_string_auth_configuration() -> None:
    with pytest.raises(ValidationError):
        ScanConfig.model_validate(
            {
                "target": {
                    "openapi_path": "examples/openapi/simple_users_api.yaml",
                    "base_url": "http://localhost:8000",
                },
                "auth": {"query_param": "access_token"},
            }
        )
