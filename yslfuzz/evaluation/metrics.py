"""Evaluation metric calculation."""

from datetime import datetime
from typing import Any

from yslfuzz.models.evaluation import EvaluationMetrics, FindingMatch, GroundTruthLab


class EvaluationMetricsCalculator:
    """Calculate benchmark metrics from matches and a YSLFuzz report."""

    def calculate(
        self,
        matches: list[FindingMatch],
        report: dict[str, Any],
        ground_truth: GroundTruthLab,
    ) -> EvaluationMetrics:
        """Return thesis-friendly evaluation metrics with safe zero division."""
        true_positives = sum(1 for match in matches if match.match_status == "true_positive")
        false_positives = sum(1 for match in matches if match.match_status == "false_positive")
        false_negatives = sum(1 for match in matches if match.match_status == "false_negative")
        precision = self._rate(true_positives, true_positives + false_positives)
        recall = self._rate(true_positives, true_positives + false_negatives)
        f1_score = self._f1(precision, recall)
        metrics = report.get("metrics", {})
        payload_summary = report.get("payload_summary", {})

        return EvaluationMetrics(
            scan_run_id=str(report.get("scan_run_id") or ""),
            lab_id=ground_truth.lab_id,
            total_expected_vulnerabilities=len(ground_truth.expected_vulnerabilities),
            total_findings=self._total_findings(report),
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            endpoint_coverage=self._float(metrics.get("endpoint_coverage")),
            payload_validity_rate=self._float(metrics.get("payload_validity_rate")),
            total_requests=self._int(metrics.get("total_requests")),
            total_payloads_generated=self._total_payloads(report, "generated_by_kind"),
            total_payloads_executed=self._total_payloads(report, "executed_by_kind"),
            findings_by_severity=self._string_int_mapping(
                metrics.get("findings_by_severity")
                or report.get("severity_summary")
                or {}
            ),
            findings_by_attack_category=self._findings_by_attack_category(report),
            execution_time_seconds=self._execution_time_seconds(report),
            metadata={
                "payload_summary_present": isinstance(payload_summary, dict),
            },
        )

    def _total_findings(self, report: dict[str, Any]) -> int:
        findings = report.get("findings")
        if isinstance(findings, list):
            return len(findings)
        metrics = report.get("metrics", {})
        return self._int(metrics.get("findings_total")) if isinstance(metrics, dict) else 0

    def _total_payloads(self, report: dict[str, Any], key: str) -> int:
        payload_summary = report.get("payload_summary") or report.get("payload_generation_summary") or {}
        if not isinstance(payload_summary, dict):
            return 0
        by_kind = payload_summary.get(key)
        if not isinstance(by_kind, dict):
            return 0
        return sum(self._int(value) for value in by_kind.values())

    def _findings_by_attack_category(self, report: dict[str, Any]) -> dict[str, int]:
        summary = report.get("attack_category_summary")
        if isinstance(summary, dict):
            return self._string_int_mapping(summary)
        counts: dict[str, int] = {}
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            return counts
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            category = finding.get("attack_category")
            if category is None:
                continue
            key = str(category)
            counts[key] = counts.get(key, 0) + 1
        return {key: counts[key] for key in sorted(counts)}

    def _execution_time_seconds(self, report: dict[str, Any]) -> float | None:
        reproducibility = report.get("reproducibility", {})
        if not isinstance(reproducibility, dict):
            return None
        started_at = self._parse_datetime(reproducibility.get("started_at") or reproducibility.get("timestamp"))
        finished_at = self._parse_datetime(reproducibility.get("finished_at"))
        if started_at is None or finished_at is None:
            return None
        return max(0.0, round((finished_at - started_at).total_seconds(), 6))

    def _rate(self, numerator: int, denominator: int) -> float:
        if denominator == 0:
            return 0.0
        return round(numerator / denominator, 6)

    def _f1(self, precision: float, recall: float) -> float:
        if precision + recall == 0:
            return 0.0
        return round((2 * precision * recall) / (precision + recall), 6)

    def _int(self, value: object) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return 0

    def _float(self, value: object) -> float:
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return 0.0
        return 0.0

    def _string_int_mapping(self, value: object) -> dict[str, int]:
        if not isinstance(value, dict):
            return {}
        return {str(key): self._int(item) for key, item in sorted(value.items())}

    def _parse_datetime(self, value: object) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
