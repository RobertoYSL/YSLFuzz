from yslfuzz.config import ConfigMerger, ScanConfig


def test_config_merger_applies_cli_output_override() -> None:
    config = _config()

    merged = ConfigMerger().merge(config, {"reporting": {"output": "override.json"}})

    assert merged.reporting.output == "override.json"


def test_config_merger_applies_nested_payload_override() -> None:
    config = _config()

    merged = ConfigMerger().merge(
        config,
        {"payloads": {"include_boundary_payloads": True}},
    )

    assert merged.payloads.include_boundary_payloads is True
    assert merged.payloads.include_invalid_payloads is False


def test_config_merger_applies_auth_override_safely() -> None:
    config = _config(auth={"bearer_env": "YSLFUZZ_TOKEN"})

    merged = ConfigMerger().merge(
        config,
        {
            "auth": {
                "bearer_env": None,
                "api_key_env": "YSLFUZZ_API_KEY",
                "api_key_header": "X-API-Key",
                "cookie_env": None,
                "cookie_name": "session",
                "custom_headers": [],
            }
        },
    )

    assert merged.auth.bearer_env is None
    assert merged.auth.api_key_env == "YSLFUZZ_API_KEY"


def _config(auth: dict[str, object] | None = None) -> ScanConfig:
    data: dict[str, object] = {
        "target": {
            "openapi_path": "examples/openapi/simple_users_api.yaml",
            "base_url": "http://localhost:8000",
        }
    }
    if auth is not None:
        data["auth"] = auth
    return ScanConfig.model_validate(data)
