import json
from pathlib import Path

import pytest

from yslfuzz.benchmark import BenchmarkConfigError, BenchmarkConfigLoader
from yslfuzz.models.benchmark import BenchmarkJobConfig


def test_benchmark_config_loads_valid_json() -> None:
    config = BenchmarkConfigLoader().load("examples/benchmarks/simple_users_benchmark.json")

    assert config.benchmark_id == "simple_users_benchmark"
    assert config.jobs[0].job_id == "simple_users_dry_run"


def test_benchmark_config_rejects_missing_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"benchmark_id": "missing"}), encoding="utf-8")

    with pytest.raises(BenchmarkConfigError, match="Invalid benchmark config"):
        BenchmarkConfigLoader().load(path)


def test_benchmark_config_defaults_are_safe() -> None:
    config = BenchmarkConfigLoader().load("examples/benchmarks/simple_users_benchmark.json")

    assert config.jobs[0].dry_run is True
    assert config.jobs[0].allow_destructive is False


def test_benchmark_job_defaults_are_safe() -> None:
    job = BenchmarkJobConfig(
        job_id="job_1",
        job_name="Job",
        target_name="target",
        base_url="http://localhost:8000",
        openapi_path="examples/openapi/simple_users_api.yaml",
    )

    assert job.dry_run is True
    assert job.execute_attacks is False
    assert job.execute_mutations is False
    assert job.include_attack_payloads is False


def test_config_hash_is_deterministic() -> None:
    loader = BenchmarkConfigLoader()
    config = loader.load("examples/benchmarks/simple_users_benchmark.json")

    assert loader.config_hash(config) == loader.config_hash(config.model_copy(deep=True))


def test_execute_attacks_requires_explicit_config_authorization() -> None:
    with pytest.raises(ValueError, match="execute_attacks requires"):
        BenchmarkJobConfig(
            job_id="job_1",
            job_name="Job",
            target_name="target",
            base_url="http://localhost:8000",
            openapi_path="examples/openapi/simple_users_api.yaml",
            execute_attacks=True,
        )


def test_execute_mutations_requires_explicit_config_authorization() -> None:
    with pytest.raises(ValueError, match="execute_mutations requires"):
        BenchmarkJobConfig(
            job_id="job_1",
            job_name="Job",
            target_name="target",
            base_url="http://localhost:8000",
            openapi_path="examples/openapi/simple_users_api.yaml",
            execute_mutations=True,
        )
