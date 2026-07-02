import json
from pathlib import Path

import pytest

from yslfuzz.benchmark import BenchmarkRunner
from yslfuzz.models.benchmark import BenchmarkConfig, BenchmarkJobConfig


def test_benchmark_auth_config_accepts_env_var_references_only() -> None:
    job = BenchmarkJobConfig(
        job_id="job_auth",
        job_name="Auth Job",
        target_name="target",
        base_url="http://localhost:8000",
        openapi_path="examples/openapi/simple_users_api.yaml",
        auth_bearer_env="YSLFUZZ_TOKEN",
    )

    assert job.auth_bearer_env == "YSLFUZZ_TOKEN"


def test_benchmark_auth_config_rejects_raw_secret_values() -> None:
    with pytest.raises(ValueError, match="raw credential values"):
        BenchmarkJobConfig(
            job_id="job_auth",
            job_name="Auth Job",
            target_name="target",
            base_url="http://localhost:8000",
            openapi_path="examples/openapi/simple_users_api.yaml",
            auth_bearer_env="eyJhbGciOi.raw.jwt",
        )


def test_benchmark_auth_config_redacts_scan_report_and_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_BENCHMARK")
    config = BenchmarkConfig(
        benchmark_id="benchmark_auth",
        benchmark_name="Benchmark Auth",
        benchmark_version="0.1.0",
        jobs=[
            BenchmarkJobConfig(
                job_id="job_auth",
                job_name="Auth Job",
                target_name="target",
                base_url="http://localhost:8000",
                openapi_path="examples/openapi/simple_users_api.yaml",
                dry_run=True,
                max_requests=1,
                auth_bearer_env="YSLFUZZ_TOKEN",
            )
        ],
    )

    result = BenchmarkRunner(config, tmp_path / "out").run()
    report_path = tmp_path / "out" / "jobs" / "job_auth" / "scan_report.json"
    metadata_path = tmp_path / "out" / "jobs" / "job_auth" / "job_metadata.json"

    assert result.status == "completed"
    assert json.loads(report_path.read_text(encoding="utf-8"))["metadata"][
        "authentication_enabled"
    ]
    assert "SENTINEL_BENCHMARK" not in report_path.read_text(encoding="utf-8")
    assert "SENTINEL_BENCHMARK" not in metadata_path.read_text(encoding="utf-8")
