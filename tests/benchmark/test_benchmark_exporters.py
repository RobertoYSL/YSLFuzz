import csv
import json
from pathlib import Path

from yslfuzz.benchmark.exporters import BENCHMARK_SUMMARY_HEADERS, BenchmarkSummaryExporter
from yslfuzz.models.benchmark import BenchmarkJobResult, BenchmarkRunResult


def test_benchmark_exporter_writes_manifest_and_summaries(tmp_path: Path) -> None:
    result = _result()
    paths = BenchmarkSummaryExporter().write_all(result, tmp_path)

    assert paths["manifest"].exists()
    assert paths["summary_json"].exists()
    assert paths["summary_csv"].exists()


def test_benchmark_manifest_includes_version_hash_and_environment(tmp_path: Path) -> None:
    path = BenchmarkSummaryExporter().write_manifest(_result(), tmp_path / "manifest.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["yslfuzz_version"]
    assert data["config_hash"] == "hash"
    assert data["environment"]["python_version"]
    assert data["environment"]["platform"]


def test_benchmark_summary_csv_has_deterministic_headers(tmp_path: Path) -> None:
    path = BenchmarkSummaryExporter().write_summary_csv(_result(), tmp_path / "summary.csv")

    with path.open(encoding="utf-8", newline="") as handle:
        headers = next(csv.reader(handle))

    assert headers == BENCHMARK_SUMMARY_HEADERS


def _result() -> BenchmarkRunResult:
    return BenchmarkRunResult(
        benchmark_id="benchmark_1",
        benchmark_name="Benchmark",
        benchmark_version="0.1.0",
        status="completed",
        config_hash="hash",
        jobs=[
            BenchmarkJobResult(
                job_id="job_1",
                job_name="Job",
                target_name="target",
                status="completed",
                scan_report_path="jobs/job_1/scan_report.json",
                metrics_summary={
                    "total_endpoints": 1,
                    "endpoint_coverage": 1.0,
                    "findings_total": 0,
                },
            )
        ],
    )
