"""Deterministic finding-to-ground-truth matching."""

from typing import Any

from yslfuzz.models.enums import AttackCategory, FindingSeverity, HttpMethod
from yslfuzz.models.evaluation import ExpectedVulnerability, FindingMatch, GroundTruthLab


class FindingMatcher:
    """Match enriched YSLFuzz findings against ground-truth vulnerabilities."""

    def match(self, report: dict[str, Any], ground_truth: GroundTruthLab) -> list[FindingMatch]:
        """Return deterministic true-positive, false-positive, and false-negative matches."""
        scan_run_id = str(report.get("scan_run_id") or "")
        findings = self._findings(report)
        unmatched_findings = list(findings)
        matches: list[FindingMatch] = []

        for expected in sorted(
            ground_truth.expected_vulnerabilities,
            key=lambda item: item.ground_truth_id,
        ):
            candidate = self._best_candidate(expected, unmatched_findings)
            if candidate is None:
                matches.append(self._false_negative(scan_run_id, expected))
                continue
            unmatched_findings.remove(candidate)
            matches.append(self._true_positive(scan_run_id, expected, candidate))

        for finding in sorted(unmatched_findings, key=self._finding_sort_key):
            matches.append(self._false_positive(scan_run_id, finding))

        return sorted(matches, key=self._match_sort_key)

    def _findings(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        value = report.get("enriched_findings") or report.get("findings") or []
        return [item for item in value if isinstance(item, dict)]

    def _best_candidate(
        self,
        expected: ExpectedVulnerability,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        candidates = [finding for finding in findings if self._matches(expected, finding)]
        if not candidates:
            return None
        return sorted(candidates, key=self._finding_sort_key)[0]

    def _matches(self, expected: ExpectedVulnerability, finding: dict[str, Any]) -> bool:
        if self._normalize_path(finding.get("endpoint_path")) != self._normalize_path(
            expected.endpoint_path
        ):
            return False
        if str(finding.get("endpoint_method") or "").upper() != expected.endpoint_method.value:
            return False
        if str(finding.get("attack_category") or "") != expected.attack_category.value:
            return False
        expected_parameter = expected.affected_parameter
        finding_parameter = finding.get("affected_parameter")
        if expected_parameter and finding_parameter and str(finding_parameter) != expected_parameter:
            return False
        return True

    def _true_positive(
        self,
        scan_run_id: str,
        expected: ExpectedVulnerability,
        finding: dict[str, Any],
    ) -> FindingMatch:
        return FindingMatch(
            scan_run_id=scan_run_id,
            match_status="true_positive",
            finding_id=self._optional_str(finding.get("finding_id")),
            ground_truth_id=expected.ground_truth_id,
            endpoint_method=expected.endpoint_method,
            endpoint_path=expected.endpoint_path,
            attack_category=expected.attack_category,
            expected_severity=expected.expected_severity,
            finding_severity=self._severity(finding.get("severity")),
            affected_parameter=expected.affected_parameter or self._optional_str(
                finding.get("affected_parameter")
            ),
            reason="endpoint, method, and attack category matched ground truth",
        )

    def _false_negative(self, scan_run_id: str, expected: ExpectedVulnerability) -> FindingMatch:
        return FindingMatch(
            scan_run_id=scan_run_id,
            match_status="false_negative",
            ground_truth_id=expected.ground_truth_id,
            endpoint_method=expected.endpoint_method,
            endpoint_path=expected.endpoint_path,
            attack_category=expected.attack_category,
            expected_severity=expected.expected_severity,
            affected_parameter=expected.affected_parameter,
            reason="ground-truth vulnerability had no matching finding",
            metadata={"classification": "unmatched_ground_truth"},
        )

    def _false_positive(self, scan_run_id: str, finding: dict[str, Any]) -> FindingMatch:
        return FindingMatch(
            scan_run_id=scan_run_id,
            match_status="false_positive",
            finding_id=self._optional_str(finding.get("finding_id")),
            endpoint_method=self._method(finding.get("endpoint_method")),
            endpoint_path=self._optional_str(finding.get("endpoint_path")),
            attack_category=self._category(finding.get("attack_category")),
            finding_severity=self._severity(finding.get("severity")),
            affected_parameter=self._optional_str(finding.get("affected_parameter")),
            reason="finding had no matching ground-truth vulnerability",
            metadata={"classification": "unmatched_finding"},
        )

    def _finding_sort_key(self, finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
        return (
            str(finding.get("endpoint_path") or ""),
            str(finding.get("endpoint_method") or ""),
            str(finding.get("attack_category") or ""),
            str(finding.get("title") or ""),
            str(finding.get("finding_id") or ""),
        )

    def _match_sort_key(self, match: FindingMatch) -> tuple[str, str, str, str, str]:
        return (
            match.endpoint_path or "",
            match.endpoint_method.value if match.endpoint_method is not None else "",
            match.attack_category.value if match.attack_category is not None else "",
            match.ground_truth_id or "",
            match.finding_id or "",
        )

    def _normalize_path(self, value: object) -> str:
        text = str(value or "")
        if not text.startswith("/"):
            return f"/{text}"
        return text

    def _method(self, value: object) -> HttpMethod | None:
        if value is None:
            return None
        try:
            return HttpMethod(str(value).upper())
        except ValueError:
            return None

    def _category(self, value: object) -> AttackCategory | None:
        if value is None:
            return None
        try:
            return AttackCategory(str(value))
        except ValueError:
            return None

    def _severity(self, value: object) -> FindingSeverity | None:
        if value is None:
            return None
        try:
            return FindingSeverity(str(value))
        except ValueError:
            return None

    def _optional_str(self, value: object) -> str | None:
        return str(value) if value is not None else None
