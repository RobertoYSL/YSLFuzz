from yslfuzz.benchmark.runner import BenchmarkRunner
from pathlib import Path

from yslfuzz.models import BenchmarkConfig, BenchmarkJobConfig


def test_benchmark_summary_includes_stability_fields(tmp_path: Path) -> None:
    runner = BenchmarkRunner(
        BenchmarkConfig(
            benchmark_id="benchmark_1",
            benchmark_name="Benchmark",
            benchmark_version="1.0",
            jobs=[
                BenchmarkJobConfig(
                    job_id="job_1",
                    job_name="Job",
                    target_name="Target",
                    base_url="http://localhost:8000",
                    openapi_path="examples/openapi/simple_users_api.yaml",
                )
            ],
        ),
        output_dir=str(tmp_path),
    )
    summary = runner._scan_metrics_summary(
        {
            "metrics": {"total_endpoints": 1, "tested_endpoints": 1, "total_requests": 1},
            "payload_summary": {"generated_by_kind": {"VALID": 1}, "executed_by_kind": {"VALID": 1}},
            "stability_summary": {
                "duration_seconds": 0.1,
                "scan_status": "completed",
                "total_retries_attempted": 1,
                "requests_skipped_due_to_budget": 2,
                "timed_out": False,
            },
        }
    )

    assert summary["scan_status"] == "completed"
    assert summary["total_retries_attempted"] == 1
    assert summary["skipped_due_to_budget"] == 2
