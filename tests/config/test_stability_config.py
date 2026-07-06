from pathlib import Path

from yslfuzz.config import ScanConfigLoader


def test_config_stability_fields_load(tmp_path: Path) -> None:
    schema_path = Path("examples/openapi/simple_users_api.yaml").resolve()
    config_path = tmp_path / "stability.yaml"
    config_path.write_text(
        f"""
target:
  openapi_path: {schema_path}
  base_url: http://localhost:8000
limits:
  max_requests: 10
  max_requests_per_endpoint: 2
  max_duration_seconds: 30
stability:
  rate_limit_rps: 2.0
  min_request_delay_ms: 100
  progress: true
  retry:
    enabled: true
    max_retries: 2
    retry_on_status_codes: [429, 500]
    backoff_initial_ms: 50
    backoff_max_ms: 500
execution:
  dry_run: true
reporting:
  output: report.json
""",
        encoding="utf-8",
    )

    config = ScanConfigLoader().load(config_path)

    assert config.execution.max_requests == 10
    assert config.limits.max_requests_per_endpoint == 2
    assert config.stability.rate_limit_rps == 2.0
    assert config.stability.retry.max_retries == 2

