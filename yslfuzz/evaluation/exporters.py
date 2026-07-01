"""Benchmark evaluation JSON and CSV exporters."""

import csv
import json
from pathlib import Path
from typing import Any, cast

from yslfuzz import __version__
from yslfuzz.models.evaluation import EvaluationReport
from yslfuzz.reporting.redaction import redact_report_value


FINDINGS_HEADERS = [
    "scan_run_id",
    "finding_id",
    "endpoint_method",
    "endpoint_path",
    "attack_category",
    "severity",
    "confidence",
    "detector_name",
    "affected_parameter",
    "affected_location",
    "fingerprint",
    "matched_ground_truth_id",
    "match_status",
]

ENDPOINT_HEADERS = [
    "scan_run_id",
    "endpoint_id",
    "method",
    "path",
    "tested",
    "request_count",
    "finding_count",
    "highest_severity",
]

MATCH_HEADERS = [
    "scan_run_id",
    "ground_truth_id",
    "endpoint_method",
    "endpoint_path",
    "attack_category",
    "expected_severity",
    "matched_finding_id",
    "match_status",
]

METRIC_HEADERS = [
    "scan_run_id",
    "lab_id",
    "total_expected_vulnerabilities",
    "total_findings",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision",
    "recall",
    "f1_score",
    "endpoint_coverage",
    "payload_validity_rate",
    "total_requests",
    "total_payloads_generated",
    "total_payloads_executed",
]


class EvaluationExporter:
    """Write evaluation reports as JSON and thesis-friendly CSV tables."""

    def write_all(
        self,
        evaluation_report: EvaluationReport,
        output_dir: str | Path,
        *,
        source_report: dict[str, Any] | None = None,
    ) -> dict[str, Path]:
        """Write JSON, findings, endpoints, matches, and metrics exports."""
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        report = source_report or {}
        paths = {
            "json": directory / "evaluation.json",
            "findings_csv": directory / "findings.csv",
            "endpoints_csv": directory / "endpoints.csv",
            "matches_csv": directory / "matches.csv",
            "metrics_csv": directory / "metrics.csv",
        }
        self.write_json(evaluation_report, paths["json"])
        self.write_findings_csv(evaluation_report, report, paths["findings_csv"])
        self.write_endpoints_csv(evaluation_report, report, paths["endpoints_csv"])
        self.write_matches_csv(evaluation_report, paths["matches_csv"])
        self.write_metrics_csv(evaluation_report, paths["metrics_csv"])
        return paths

    def write_json(self, evaluation_report: EvaluationReport, path: str | Path) -> Path:
        """Write a redacted JSON evaluation result."""
        output_path = Path(path)
        output_path.write_text(
            json.dumps(self.to_dict(evaluation_report), indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        return output_path

    def to_dict(self, evaluation_report: EvaluationReport) -> dict[str, Any]:
        """Convert an evaluation report to a redacted JSON dictionary."""
        data = evaluation_report.model_dump(mode="json")
        data["yslfuzz_version"] = __version__
        return cast(dict[str, Any], redact_report_value(data))

    def write_findings_csv(
        self,
        evaluation_report: EvaluationReport,
        source_report: dict[str, Any],
        path: str | Path,
    ) -> Path:
        """Write findings.csv."""
        match_by_finding_id = {
            match.finding_id: match
            for match in evaluation_report.matches
            if match.finding_id is not None
        }
        rows = []
        for finding in self._findings(source_report):
            match = match_by_finding_id.get(str(finding.get("finding_id")))
            rows.append(
                {
                    "scan_run_id": evaluation_report.scan_run_id,
                    "finding_id": finding.get("finding_id"),
                    "endpoint_method": finding.get("endpoint_method"),
                    "endpoint_path": finding.get("endpoint_path"),
                    "attack_category": finding.get("attack_category"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "detector_name": finding.get("detector_name"),
                    "affected_parameter": finding.get("affected_parameter"),
                    "affected_location": finding.get("affected_location"),
                    "fingerprint": finding.get("fingerprint_hash") or finding.get("fingerprint"),
                    "matched_ground_truth_id": match.ground_truth_id if match else "",
                    "match_status": match.match_status if match else "unmatched_finding",
                }
            )
        return self._write_csv(path, FINDINGS_HEADERS, rows)

    def write_endpoints_csv(
        self,
        evaluation_report: EvaluationReport,
        source_report: dict[str, Any],
        path: str | Path,
    ) -> Path:
        """Write endpoints.csv."""
        rows = [
            {
                "scan_run_id": evaluation_report.scan_run_id,
                "endpoint_id": endpoint.get("endpoint_id"),
                "method": endpoint.get("method"),
                "path": endpoint.get("path"),
                "tested": endpoint.get("tested"),
                "request_count": endpoint.get("request_count"),
                "finding_count": endpoint.get("finding_count"),
                "highest_severity": endpoint.get("highest_severity"),
            }
            for endpoint in self._endpoint_summary(source_report)
        ]
        return self._write_csv(path, ENDPOINT_HEADERS, rows)

    def write_matches_csv(self, evaluation_report: EvaluationReport, path: str | Path) -> Path:
        """Write matches.csv."""
        rows = [
            {
                "scan_run_id": match.scan_run_id,
                "ground_truth_id": match.ground_truth_id or "",
                "endpoint_method": match.endpoint_method.value if match.endpoint_method else "",
                "endpoint_path": match.endpoint_path or "",
                "attack_category": match.attack_category.value if match.attack_category else "",
                "expected_severity": match.expected_severity.value if match.expected_severity else "",
                "matched_finding_id": match.finding_id or "",
                "match_status": match.match_status,
            }
            for match in evaluation_report.matches
        ]
        return self._write_csv(path, MATCH_HEADERS, rows)

    def write_metrics_csv(self, evaluation_report: EvaluationReport, path: str | Path) -> Path:
        """Write metrics.csv."""
        metrics = evaluation_report.metrics
        row = {
            "scan_run_id": metrics.scan_run_id,
            "lab_id": metrics.lab_id,
            "total_expected_vulnerabilities": metrics.total_expected_vulnerabilities,
            "total_findings": metrics.total_findings,
            "true_positives": metrics.true_positives,
            "false_positives": metrics.false_positives,
            "false_negatives": metrics.false_negatives,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
            "endpoint_coverage": metrics.endpoint_coverage,
            "payload_validity_rate": metrics.payload_validity_rate,
            "total_requests": metrics.total_requests,
            "total_payloads_generated": metrics.total_payloads_generated,
            "total_payloads_executed": metrics.total_payloads_executed,
        }
        return self._write_csv(path, METRIC_HEADERS, [row])

    def _write_csv(
        self,
        path: str | Path,
        headers: list[str],
        rows: list[dict[str, Any]],
    ) -> Path:
        output_path = Path(path)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(redact_report_value(row))
        return output_path

    def _findings(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        findings = report.get("enriched_findings") or report.get("findings") or []
        return [finding for finding in findings if isinstance(finding, dict)]

    def _endpoint_summary(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        endpoints = report.get("endpoint_summary") or []
        return [endpoint for endpoint in endpoints if isinstance(endpoint, dict)]
