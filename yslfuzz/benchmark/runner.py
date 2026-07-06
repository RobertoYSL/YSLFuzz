"""Benchmark runner orchestration."""

import argparse
import json
from pathlib import Path
from time import perf_counter
from typing import Any

from yslfuzz.benchmark.config import BenchmarkConfigLoader
from yslfuzz.benchmark.exporters import BenchmarkSummaryExporter, environment_summary
from yslfuzz.evaluation import (
    EvaluationExporter,
    EvaluationMetricsCalculator,
    FindingMatcher,
    GroundTruthLoader,
)
from yslfuzz.models.base import utc_now
from yslfuzz.models.benchmark import (
    BenchmarkArtifact,
    BenchmarkConfig,
    BenchmarkJobConfig,
    BenchmarkJobResult,
    BenchmarkRunResult,
)
from yslfuzz.models.evaluation import EvaluationReport


class BenchmarkRunner:
    """Execute one or more scan/evaluation jobs from a benchmark config."""

    def __init__(
        self,
        config: BenchmarkConfig,
        output_dir: str | Path,
        *,
        fail_fast: bool = False,
        force_dry_run: bool = False,
        overwrite: bool = False,
        verbose: bool = False,
    ) -> None:
        self.config = config
        self.output_dir = Path(output_dir)
        self.fail_fast = fail_fast
        self.force_dry_run = force_dry_run
        self.overwrite = overwrite
        self.verbose = verbose
        self._config_hash = BenchmarkConfigLoader().config_hash(config)

    def run(self) -> BenchmarkRunResult:
        """Run all benchmark jobs and write manifest and summary exports."""
        self._prepare_output_dir()
        started_at = utc_now()
        start = perf_counter()
        result = BenchmarkRunResult(
            benchmark_id=self.config.benchmark_id,
            benchmark_name=self.config.benchmark_name,
            benchmark_version=self.config.benchmark_version,
            status="completed",
            started_at=started_at,
            random_seed=self.config.random_seed,
            config_hash=self._config_hash,
            environment=environment_summary(),
        )

        for job in self.config.jobs:
            if self.verbose:
                print(f"Running benchmark job {job.job_id}: {job.job_name}")
            job_result = self._run_job(job)
            result.jobs.append(job_result)
            if job_result.status == "failed":
                result.status = "failed"
                if self.fail_fast:
                    break

        result.finished_at = utc_now()
        result.duration_seconds = round(perf_counter() - start, 6)
        artifacts = BenchmarkSummaryExporter().write_all(result, self.output_dir)
        result.artifacts.extend(
            [
                BenchmarkArtifact(artifact_type="manifest", path=str(artifacts["manifest"])),
                BenchmarkArtifact(artifact_type="summary_json", path=str(artifacts["summary_json"])),
                BenchmarkArtifact(artifact_type="summary_csv", path=str(artifacts["summary_csv"])),
            ]
        )
        BenchmarkSummaryExporter().write_all(result, self.output_dir)
        return result

    def _run_job(self, job: BenchmarkJobConfig) -> BenchmarkJobResult:
        started_at = utc_now()
        start = perf_counter()
        job_dir = self.output_dir / "jobs" / job.effective_output_subdir
        job_dir.mkdir(parents=True, exist_ok=True)
        scan_report_path = job_dir / "scan_report.json"
        result = BenchmarkJobResult(
            job_id=job.job_id,
            job_name=job.job_name,
            target_name=job.target_name,
            status="completed",
            started_at=started_at,
            scan_report_path=str(scan_report_path),
            reproducibility={
                "dry_run": self.force_dry_run or job.dry_run,
                "random_seed": self.config.random_seed,
            },
        )

        try:
            self._validate_job_paths(job)
            self._run_scan(job, scan_report_path)
            report = self._load_report(scan_report_path)
            result.metrics_summary.update(self._scan_metrics_summary(report))
            result.artifacts.append(
                BenchmarkArtifact(artifact_type="scan_report", path=str(scan_report_path))
            )
            if job.ground_truth_path:
                evaluation_dir = job_dir / "evaluation"
                evaluation_paths = self._run_evaluation(report, job.ground_truth_path, evaluation_dir)
                result.evaluation_output_dir = str(evaluation_dir)
                result.metrics_summary.update(self._evaluation_metrics_summary(evaluation_paths["json"]))
                result.artifacts.extend(
                    BenchmarkArtifact(artifact_type=name, path=str(path))
                    for name, path in sorted(evaluation_paths.items())
                )
            self._write_job_metadata(result, job_dir / "job_metadata.json")
        except Exception as exc:  # noqa: BLE001 - benchmark jobs must record failures.
            result.status = "failed"
            result.error_message = str(exc)
            self._write_job_metadata(result, job_dir / "job_metadata.json")
        finally:
            result.finished_at = utc_now()
            result.duration_seconds = round(perf_counter() - start, 6)
            self._write_job_metadata(result, job_dir / "job_metadata.json")
        return result

    def _run_scan(self, job: BenchmarkJobConfig, scan_report_path: Path) -> None:
        from yslfuzz.cli.main import run_scan_command

        args = argparse.Namespace(
            openapi=job.openapi_path,
            base_url=job.base_url,
            output=str(scan_report_path),
            max_requests=job.max_requests,
            timeout=job.timeout,
            allow_destructive=job.allow_destructive,
            dry_run=self.force_dry_run or job.dry_run,
            verbose=False,
            include_attack_payloads=job.include_attack_payloads,
            execute_attacks=job.execute_attacks,
            attack_category=[category.value for category in job.enabled_attack_categories],
            max_attack_requests_per_endpoint=job.max_attack_requests_per_endpoint,
            i_understand_this_is_authorized=job.i_understand_attack_execution_is_authorized,
            no_deduplicate_findings=False,
            disable_detector=[],
            analysis_min_confidence=None,
            include_boundary_payloads=job.include_boundary_payloads,
            include_invalid_payloads=job.include_invalid_payloads,
            include_mutated_payloads=job.include_mutated_payloads,
            max_mutations_per_payload=job.max_mutations_per_payload,
            max_mutations_per_field=job.max_mutations_per_field,
            mutate_sensitive_fields=False,
            allow_invalid_enum_values=False,
            disable_type_confusion=False,
            disable_boundary_values=False,
            disable_null_mutations=False,
            execute_mutations=job.execute_mutations,
            i_understand_mutation_execution_is_authorized=(
                job.i_understand_mutation_execution_is_authorized
            ),
            auth_bearer_env=job.auth_bearer_env,
            auth_api_key_env=job.auth_api_key_env,
            auth_api_key_header=job.auth_api_key_header,
            auth_cookie_env=job.auth_cookie_env,
            auth_cookie_name=job.auth_cookie_name,
            auth_header=list(job.auth_headers),
        )
        run_scan_command(args)

    def _run_evaluation(
        self,
        report: dict[str, Any],
        ground_truth_path: str,
        evaluation_dir: Path,
    ) -> dict[str, Path]:
        ground_truth = GroundTruthLoader().load(ground_truth_path)
        matches = FindingMatcher().match(report, ground_truth)
        metrics = EvaluationMetricsCalculator().calculate(matches, report, ground_truth)
        evaluation_report = EvaluationReport(
            scan_run_id=metrics.scan_run_id,
            lab=ground_truth,
            metrics=metrics,
            matches=matches,
            reproducibility={
                "scan_run_id": metrics.scan_run_id,
                "lab_id": ground_truth.lab_id,
                "lab_version": ground_truth.lab_version,
                "report_schema_version": report.get("report_schema_version"),
                "random_seed": self.config.random_seed,
                "evaluation_generated_at": utc_now().isoformat(),
                "detectors": report.get("reproducibility", {}).get("detectors", [])
                if isinstance(report.get("reproducibility"), dict)
                else [],
            },
        )
        paths = EvaluationExporter().write_all(
            evaluation_report,
            evaluation_dir,
            source_report=report,
        )
        evaluation_report_path = evaluation_dir / "evaluation_report.json"
        EvaluationExporter().write_json(evaluation_report, evaluation_report_path)
        paths["evaluation_report_json"] = evaluation_report_path
        return paths

    def _prepare_output_dir(self) -> None:
        if self.output_dir.exists() and not self.overwrite:
            raise FileExistsError(
                f"Benchmark output directory already exists: {self.output_dir}. Use overwrite to reuse it."
            )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "jobs").mkdir(parents=True, exist_ok=True)

    def _validate_job_paths(self, job: BenchmarkJobConfig) -> None:
        if not Path(job.openapi_path).is_file():
            raise FileNotFoundError(f"OpenAPI file does not exist: {job.openapi_path}")
        if job.ground_truth_path is not None and not Path(job.ground_truth_path).is_file():
            raise FileNotFoundError(f"Ground-truth file does not exist: {job.ground_truth_path}")

    def _load_report(self, path: Path) -> dict[str, Any]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("scan report root must be an object")
        return data

    def _scan_metrics_summary(self, report: dict[str, Any]) -> dict[str, Any]:
        metrics = report.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}
        payload_summary = report.get("payload_summary", {})
        if not isinstance(payload_summary, dict):
            payload_summary = {}
        generated = payload_summary.get("generated_by_kind", {})
        executed = payload_summary.get("executed_by_kind", {})
        return {
            "total_endpoints": metrics.get("total_endpoints"),
            "tested_endpoints": metrics.get("tested_endpoints"),
            "endpoint_coverage": metrics.get("endpoint_coverage"),
            "total_requests": metrics.get("total_requests"),
            "total_payloads_generated": self._sum_mapping(generated),
            "total_payloads_executed": self._sum_mapping(executed),
            "findings_total": metrics.get("findings_total"),
            **self._stability_metrics_summary(report),
        }

    def _stability_metrics_summary(self, report: dict[str, Any]) -> dict[str, Any]:
        stability = report.get("stability_summary", {})
        if not isinstance(stability, dict):
            return {}
        return {
            "duration_seconds": stability.get("duration_seconds"),
            "scan_status": stability.get("scan_status"),
            "total_retries_attempted": stability.get("total_retries_attempted"),
            "skipped_due_to_budget": stability.get("requests_skipped_due_to_budget"),
            "timed_out": stability.get("timed_out"),
            "cancelled": stability.get("scan_status") == "cancelled",
        }

    def _evaluation_metrics_summary(self, evaluation_json_path: Path) -> dict[str, Any]:
        data = self._load_report(evaluation_json_path)
        metrics = data.get("metrics", {})
        if not isinstance(metrics, dict):
            return {}
        return {
            "true_positives": metrics.get("true_positives"),
            "false_positives": metrics.get("false_positives"),
            "false_negatives": metrics.get("false_negatives"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1_score": metrics.get("f1_score"),
        }

    def _write_job_metadata(self, result: BenchmarkJobResult, path: Path) -> None:
        path.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

    def _sum_mapping(self, value: object) -> int:
        if not isinstance(value, dict):
            return 0
        total = 0
        for item in value.values():
            if isinstance(item, int):
                total += item
            elif isinstance(item, float):
                total += int(item)
        return total
