"""Evaluation command handler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from yslfuzz import __version__
from yslfuzz.evaluation import (
    EvaluationExporter,
    EvaluationMetricsCalculator,
    FindingMatcher,
    GroundTruthLoader,
)
from yslfuzz.models.base import utc_now
from yslfuzz.models.evaluation import EvaluationReport


def _load_report_dict(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Report root must be a JSON object")
    return data


def _evaluation_reproducibility(
    report: dict[str, object],
    ground_truth: object,
) -> dict[str, object]:
    reproducibility = report.get("reproducibility", {})
    if not isinstance(reproducibility, dict):
        reproducibility = {}
    analysis_summary = report.get("analysis_summary")
    detector_list: object = []
    if isinstance(analysis_summary, dict):
        detector_list = analysis_summary.get("detectors", [])
    lab_id = getattr(ground_truth, "lab_id", None)
    lab_version = getattr(ground_truth, "lab_version", None)
    return {
        "yslfuzz_version": __version__,
        "report_schema_version": report.get("report_schema_version"),
        "scan_run_id": report.get("scan_run_id"),
        "lab_id": lab_id,
        "lab_version": lab_version,
        "random_seed": reproducibility.get("random_seed"),
        "generated_at": report.get("generated_at"),
        "evaluation_generated_at": utc_now().isoformat(),
        "detectors": detector_list or reproducibility.get("detectors", []),
        "enabled_payload_modes": reproducibility.get("enabled_payload_modes", []),
        "attack_execution_enabled": bool(reproducibility.get("attack_execution_enabled", False)),
        "mutation_execution_enabled": bool(reproducibility.get("mutation_execution_enabled", False)),
    }


def run_evaluate_command(args: argparse.Namespace) -> int:
    """Run the evaluation command and return a process exit code."""
    report_path = Path(args.report)
    ground_truth_path = Path(args.ground_truth)
    output_dir = Path(args.output_dir)
    if not report_path.is_file():
        raise FileNotFoundError(f"Report file does not exist: {report_path}")
    if not ground_truth_path.is_file():
        raise FileNotFoundError(f"Ground-truth file does not exist: {ground_truth_path}")

    report = _load_report_dict(report_path)
    ground_truth = GroundTruthLoader().load(ground_truth_path)
    matches = FindingMatcher().match(report, ground_truth)
    metrics = EvaluationMetricsCalculator().calculate(matches, report, ground_truth)
    evaluation_report = EvaluationReport(
        scan_run_id=metrics.scan_run_id,
        lab=ground_truth,
        metrics=metrics,
        matches=matches,
        reproducibility=_evaluation_reproducibility(report, ground_truth),
    )
    paths = EvaluationExporter().write_all(
        evaluation_report,
        output_dir,
        source_report=report,
    )
    print(
        "YSLFuzz evaluation complete: "
        f"scan_run_id={metrics.scan_run_id}, lab_id={metrics.lab_id}, "
        f"tp={metrics.true_positives}, fp={metrics.false_positives}, "
        f"fn={metrics.false_negatives}, precision={metrics.precision}, "
        f"recall={metrics.recall}, f1={metrics.f1_score}, "
        f"output_dir={paths['json'].parent}"
    )
    return 0
