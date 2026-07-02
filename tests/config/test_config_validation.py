import pytest

from yslfuzz.config import ConfigValidationError, ConfigValidator, ScanConfig


def test_config_validation_rejects_execute_attacks_without_authorization() -> None:
    config = _config({"execute_attacks": True})

    with pytest.raises(ConfigValidationError, match="execute_attacks requires"):
        ConfigValidator().validate(config)


def test_config_validation_accepts_execute_attacks_with_authorization() -> None:
    config = _config(
        {
            "execute_attacks": True,
            "i_understand_attack_execution_is_authorized": True,
        }
    )

    ConfigValidator().validate(config)


def test_config_validation_rejects_execute_mutations_without_authorization() -> None:
    config = _config({"execute_mutations": True})

    with pytest.raises(ConfigValidationError, match="execute_mutations requires"):
        ConfigValidator().validate(config)


def test_config_validation_accepts_execute_mutations_with_authorization() -> None:
    config = _config(
        {
            "execute_mutations": True,
            "i_understand_mutation_execution_is_authorized": True,
        }
    )

    ConfigValidator().validate(config)


def _config(execution: dict[str, object]) -> ScanConfig:
    return ScanConfig.model_validate(
        {
            "target": {
                "openapi_path": "examples/openapi/simple_users_api.yaml",
                "base_url": "http://localhost:8000",
            },
            "execution": execution,
        }
    )
