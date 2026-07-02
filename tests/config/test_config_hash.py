from yslfuzz.config import ConfigHasher, ScanConfig


def test_config_hash_is_deterministic() -> None:
    config = _config()

    assert ConfigHasher().hash(config) == ConfigHasher().hash(config.model_copy(deep=True))


def test_config_hash_does_not_include_timestamps() -> None:
    first = _config()
    second = _config()
    first.config_loaded_at = "2026-07-02T10:00:00+00:00"
    second.config_loaded_at = "2026-07-02T11:00:00+00:00"

    assert ConfigHasher().hash(first) == ConfigHasher().hash(second)


def test_config_hash_does_not_include_secret_values() -> None:
    config = _config(auth={"bearer_env": "YSLFUZZ_TOKEN"})

    normalized = ConfigHasher().normalized(config)

    assert "SENTINEL_SECRET_VALUE" not in str(normalized)


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
