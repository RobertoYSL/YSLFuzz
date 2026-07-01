import json
from pathlib import Path

import pytest

from yslfuzz.benchmark import BenchmarkConfigLoader, BenchmarkRunner
from yslfuzz.models.benchmark import BenchmarkConfig, BenchmarkJobConfig


def test_runner_creates_output_directory_structure(tmp_path: Path) -> None:
    result = _run_example(tmp_path / "out")

    assert (tmp_path / "out" / "benchmark_manifest.json").exists()
    assert (tmp_path / "out" / "benchmark_summary.json").exists()
    assert (tmp_path / "out" / "benchmark_summary.csv").exists()
    assert (tmp_path / "out" / "jobs" / "simple_users_dry_run").is_dir()
    assert result.jobs[0].status == "completed"


def test_runner_fails_if_output_directory_exists_without_overwrite(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with pytest.raises(FileExistsError):
        BenchmarkRunner(_example_config(), output_dir).run()


def test_runner_supports_overwrite_behavior(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    result = BenchmarkRunner(_example_config(), output_dir, overwrite=True).run()

    assert result.status == "completed"


def test_runner_writes_job_metadata_manifest_and_summary(tmp_path: Path) -> None:
    _run_example(tmp_path / "out")
    job_dir = tmp_path / "out" / "jobs" / "simple_users_dry_run"

    assert (job_dir / "job_metadata.json").exists()
    assert json.loads((tmp_path / "out" / "benchmark_manifest.json").read_text())["config_hash"]
    assert (tmp_path / "out" / "benchmark_summary.csv").read_text(encoding="utf-8").startswith(
        "benchmark_id,job_id"
    )


def test_runner_runs_evaluation_when_ground_truth_path_is_provided(tmp_path: Path) -> None:
    _run_example(tmp_path / "out")
    evaluation_dir = tmp_path / "out" / "jobs" / "simple_users_dry_run" / "evaluation"

    assert (evaluation_dir / "evaluation_report.json").exists()
    assert (evaluation_dir / "findings.csv").exists()


def test_runner_skips_evaluation_cleanly_when_ground_truth_is_absent(tmp_path: Path) -> None:
    config = BenchmarkConfig(
        benchmark_id="benchmark_no_gt",
        benchmark_name="No GT",
        benchmark_version="0.1.0",
        jobs=[
            BenchmarkJobConfig(
                job_id="job_1",
                job_name="Job",
                target_name="target",
                base_url="http://localhost:8000",
                openapi_path="examples/openapi/simple_users_api.yaml",
                dry_run=True,
            )
        ],
    )
    result = BenchmarkRunner(config, tmp_path / "out").run()

    assert result.jobs[0].evaluation_output_dir is None
    assert not (tmp_path / "out" / "jobs" / "job_1" / "evaluation").exists()


def test_runner_records_failed_job_without_crashing(tmp_path: Path) -> None:
    result = BenchmarkRunner(_failing_config(two_jobs=False), tmp_path / "out").run()

    assert result.status == "failed"
    assert result.jobs[0].status == "failed"
    assert result.jobs[0].error_message


def test_fail_fast_stops_after_first_failed_job(tmp_path: Path) -> None:
    result = BenchmarkRunner(_failing_config(two_jobs=True), tmp_path / "out", fail_fast=True).run()

    assert len(result.jobs) == 1
    assert result.status == "failed"


def test_forced_dry_run_overrides_job_config(tmp_path: Path) -> None:
    config = BenchmarkConfig(
        benchmark_id="benchmark_force_dry",
        benchmark_name="Force Dry",
        benchmark_version="0.1.0",
        jobs=[
            BenchmarkJobConfig(
                job_id="job_1",
                job_name="Job",
                target_name="target",
                base_url="http://localhost:8000",
                openapi_path="examples/openapi/simple_users_api.yaml",
                dry_run=False,
                max_requests=1,
            )
        ],
    )
    result = BenchmarkRunner(config, tmp_path / "out", force_dry_run=True).run()

    assert result.jobs[0].reproducibility["dry_run"] is True
    report = json.loads((tmp_path / "out" / "jobs" / "job_1" / "scan_report.json").read_text())
    assert report["metadata"]["dry_run"] is True


def _run_example(output_dir: Path) -> object:
    return BenchmarkRunner(_example_config(), output_dir).run()


def _example_config() -> BenchmarkConfig:
    return BenchmarkConfigLoader().load("examples/benchmarks/simple_users_benchmark.json")


def _failing_config(two_jobs: bool) -> BenchmarkConfig:
    jobs = [
        BenchmarkJobConfig(
            job_id="job_bad",
            job_name="Bad Job",
            target_name="target",
            base_url="http://localhost:8000",
            openapi_path="examples/openapi/missing.yaml",
            dry_run=True,
        )
    ]
    if two_jobs:
        jobs.append(
            BenchmarkJobConfig(
                job_id="job_good",
                job_name="Good Job",
                target_name="target",
                base_url="http://localhost:8000",
                openapi_path="examples/openapi/simple_users_api.yaml",
                dry_run=True,
            )
        )
    return BenchmarkConfig(
        benchmark_id="benchmark_fail",
        benchmark_name="Failure",
        benchmark_version="0.1.0",
        jobs=jobs,
    )
