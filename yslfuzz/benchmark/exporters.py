"""Benchmark manifest and summary exporters."""

import csv
import json
import platform
import sys
from pathlib import Path
from typing import Any, cast

from yslfuzz import __version__
from yslfuzz.models.benchmark import BenchmarkRunResult
from yslfuzz.reporting.redaction import redact_report_value


BENCHMARK_SUMMARY_HEADERS = [
    "benchmark_id",
    "job_id",
    "job_name",
    "target_name",
    "status",
    "duration_seconds",
    "total_endpoints",
    "tested_endpoints",
    "endpoint_coverage",
    "total_requests",
    "total_payloads_generated",
    "total_payloads_executed",
    "findings_total",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision",
    "recall",
    "f1_score",
    "scan_report_path",
    "evaluation_output_dir",
]


class BenchmarkSummaryExporter:
    """Write benchmark manifest and summary exports."""

    def write_all(self, result: BenchmarkRunResult, output_dir: str | Path) -> dict[str, Path]:
        """Write benchmark_manifest.json, benchmark_summary.json, and benchmark_summary.csv."""
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        paths = {
            "manifest": directory / "benchmark_manifest.json",
            "summary_json": directory / "benchmark_summary.json",
            "summary_csv": directory / "benchmark_summary.csv",
        }
        self.write_manifest(result, paths["manifest"])
        self.write_summary_json(result, paths["summary_json"])
        self.write_summary_csv(result, paths["summary_csv"])
        return paths

    def write_manifest(self, result: BenchmarkRunResult, path: str | Path) -> Path:
        """Write benchmark_manifest.json."""
        manifest = self.manifest_dict(result)
        output_path = Path(path)
        output_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        return output_path

    def write_summary_json(self, result: BenchmarkRunResult, path: str | Path) -> Path:
        """Write benchmark_summary.json."""
        output_path = Path(path)
        output_path.write_text(
            json.dumps(self.summary_dict(result), indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        return output_path

    def write_summary_csv(self, result: BenchmarkRunResult, path: str | Path) -> Path:
        """Write benchmark_summary.csv with deterministic headers."""
        output_path = Path(path)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=BENCHMARK_SUMMARY_HEADERS)
            writer.writeheader()
            for row in self.summary_rows(result):
                writer.writerow(redact_report_value(row))
        return output_path

    def manifest_dict(self, result: BenchmarkRunResult) -> dict[str, Any]:
        """Return a redacted manifest dictionary."""
        artifacts = [artifact.model_dump(mode="json") for artifact in result.artifacts]
        for job in result.jobs:
            artifacts.extend(artifact.model_dump(mode="json") for artifact in job.artifacts)
        value = {
            "benchmark_id": result.benchmark_id,
            "benchmark_name": result.benchmark_name,
            "benchmark_version": result.benchmark_version,
            "yslfuzz_version": __version__,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "random_seed": result.random_seed,
            "config_hash": result.config_hash,
            "jobs": [job.model_dump(mode="json") for job in result.jobs],
            "artifacts": artifacts,
            "environment": result.environment or environment_summary(),
        }
        return cast(dict[str, Any], redact_report_value(value))

    def summary_dict(self, result: BenchmarkRunResult) -> dict[str, Any]:
        """Return a redacted benchmark summary dictionary."""
        value = {
            "benchmark_id": result.benchmark_id,
            "benchmark_name": result.benchmark_name,
            "benchmark_version": result.benchmark_version,
            "status": result.status,
            "duration_seconds": result.duration_seconds,
            "job_count": len(result.jobs),
            "jobs": self.summary_rows(result),
        }
        return cast(dict[str, Any], redact_report_value(value))

    def summary_rows(self, result: BenchmarkRunResult) -> list[dict[str, Any]]:
        """Return summary rows for CSV and JSON exports."""
        rows = []
        for job in sorted(result.jobs, key=lambda item: item.job_id):
            metrics = job.metrics_summary
            rows.append(
                {
                    "benchmark_id": result.benchmark_id,
                    "job_id": job.job_id,
                    "job_name": job.job_name,
                    "target_name": job.target_name,
                    "status": job.status,
                    "duration_seconds": job.duration_seconds,
                    "total_endpoints": metrics.get("total_endpoints"),
                    "tested_endpoints": metrics.get("tested_endpoints"),
                    "endpoint_coverage": metrics.get("endpoint_coverage"),
                    "total_requests": metrics.get("total_requests"),
                    "total_payloads_generated": metrics.get("total_payloads_generated"),
                    "total_payloads_executed": metrics.get("total_payloads_executed"),
                    "findings_total": metrics.get("findings_total"),
                    "true_positives": metrics.get("true_positives"),
                    "false_positives": metrics.get("false_positives"),
                    "false_negatives": metrics.get("false_negatives"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "f1_score": metrics.get("f1_score"),
                    "scan_report_path": job.scan_report_path,
                    "evaluation_output_dir": job.evaluation_output_dir,
                }
            )
        return rows


def environment_summary() -> dict[str, str]:
    """Return a small non-sensitive environment summary."""
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "yslfuzz_version": __version__,
    }
