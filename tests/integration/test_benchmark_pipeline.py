import json
from pathlib import Path

from yslfuzz.benchmark import BenchmarkConfigLoader, BenchmarkRunner


def test_benchmark_pipeline_from_example_config(tmp_path: Path) -> None:
    config = BenchmarkConfigLoader().load("examples/benchmarks/simple_users_benchmark.json")
    result = BenchmarkRunner(config, tmp_path / "benchmark").run()
    job_dir = tmp_path / "benchmark" / "jobs" / "simple_users_dry_run"

    assert result.status == "completed"
    assert (tmp_path / "benchmark" / "benchmark_manifest.json").exists()
    assert (tmp_path / "benchmark" / "benchmark_summary.json").exists()
    assert (tmp_path / "benchmark" / "benchmark_summary.csv").exists()
    assert (job_dir / "scan_report.json").exists()
    assert (job_dir / "evaluation" / "evaluation_report.json").exists()
    assert (job_dir / "evaluation" / "findings.csv").exists()
    assert (job_dir / "evaluation" / "endpoints.csv").exists()
    assert (job_dir / "evaluation" / "matches.csv").exists()
    assert (job_dir / "evaluation" / "metrics.csv").exists()

    report = json.loads((job_dir / "scan_report.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (tmp_path / "benchmark" / "benchmark_manifest.json").read_text(encoding="utf-8")
    )

    assert report["metadata"]["dry_run"] is True
    assert manifest["benchmark_id"] == "simple_users_benchmark"
    assert manifest["environment"]["python_version"]
