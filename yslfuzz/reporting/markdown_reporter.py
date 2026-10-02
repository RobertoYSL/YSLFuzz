"""Minimal Markdown report generation."""

from pathlib import Path
from typing import Any

from yslfuzz.models.reporting import Report
from yslfuzz.reporting.json_reporter import JsonReporter
from yslfuzz.reporting.redaction import redact_report_value


class MarkdownReporter:
    """Render a redacted Markdown report from a Report model."""

    def __init__(self, json_reporter: JsonReporter | None = None) -> None:
        self._json_reporter = json_reporter or JsonReporter()

    def to_markdown(self, report: Report) -> str:
        """Return a minimal redacted Markdown report."""
        data = redact_report_value(self._json_reporter.to_dict(report))
        lines = [
            "# YSLFuzz Scan Report",
            "",
            "## Target",
            "",
        ]
        lines.extend(self._target_lines(data.get("target_summary")))
        lines.extend(
            [
                "",
                "## Scan Summary",
                "",
                f"- Scan run: `{data.get('scan_run_id')}`",
                f"- Findings: `{data.get('metrics', {}).get('findings_total', 0)}`",
                f"- Requests: `{data.get('metrics', {}).get('total_requests', 0)}`",
                "",
                "## Severity Summary",
                "",
            ]
        )
        lines.extend(self._summary_table(data.get("severity_summary", {}), "Severity"))
        metadata = data.get("metadata", {})
        if isinstance(metadata, dict):
            wf = metadata.get("stateful_workflows")
            if isinstance(wf, dict) and wf.get("enabled"):
                lines.extend(
                    [
                        "",
                        "## Stateful Workflows",
                        "",
                        "- Enabled: `True`",
                        f"- Workflows detected: `{wf.get('workflows_detected', 0)}`",
                        f"- Workflows executed: `{wf.get('workflows_executed', 0)}`",
                        f"- Dynamic parameters propagated: `{wf.get('known_values_extracted', 0)}`",
                    ]
                )
        lines.extend(["", "## Endpoint Summary", ""])
        lines.extend(self._endpoint_table(data.get("endpoint_summary", [])))
        lines.extend(["", "## Findings", ""])
        lines.extend(self._finding_lines(data.get("findings", [])))
        lines.extend(["", "## Reproducibility", ""])
        lines.extend(self._metadata_lines(data.get("reproducibility", {})))
        return "\n".join(lines).rstrip() + "\n"

    def write_markdown(self, report: Report, path: str | Path) -> Path:
        """Write a redacted Markdown report to a file and return the written path."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_markdown(report), encoding="utf-8")
        return output_path

    def _target_lines(self, target: Any) -> list[str]:
        if not isinstance(target, dict) or not target:
            return ["No target metadata available."]
        return [
            f"- Target ID: `{target.get('target_id')}`",
            f"- Name: `{target.get('name')}`",
            f"- Base URL: `{target.get('base_url')}`",
            f"- API style: `{target.get('api_style')}`",
        ]

    def _summary_table(self, summary: Any, label: str) -> list[str]:
        if not isinstance(summary, dict):
            return ["No summary available."]
        lines = [f"| {label} | Count |", "|---|---:|"]
        for key in sorted(summary):
            lines.append(f"| {key} | {summary[key]} |")
        return lines

    def _endpoint_table(self, endpoints: Any) -> list[str]:
        if not isinstance(endpoints, list) or not endpoints:
            return ["No endpoint summary available."]
        lines = [
            "| Method | Path | Tested | Requests | Findings | Highest Severity |",
            "|---|---|---:|---:|---:|---|",
        ]
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
            op_str = ""
            if endpoint.get("graphql_operation_type") and endpoint.get("graphql_operation_name"):
                op_str = f" ({endpoint.get('graphql_operation_type')}: {endpoint.get('graphql_operation_name')})"
            lines.append(
                "| "
                f"{endpoint.get('method') or ''} | "
                f"{endpoint.get('path') or ''}{op_str} | "
                f"{endpoint.get('tested')} | "
                f"{endpoint.get('request_count', 0)} | "
                f"{endpoint.get('finding_count', 0)} | "
                f"{endpoint.get('highest_severity') or ''} |"
            )
        return lines

    def _finding_lines(self, findings: Any) -> list[str]:
        if not isinstance(findings, list) or not findings:
            return ["No findings."]
        lines: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            op_str = ""
            if finding.get("graphql_operation_type") and finding.get("graphql_operation_name"):
                op_str = f" ({finding.get('graphql_operation_type')}: {finding.get('graphql_operation_name')})"
            lines.extend(
                [
                    f"### {finding.get('title')}",
                    "",
                    f"- Severity: `{finding.get('severity')}`",
                    f"- Confidence: `{finding.get('confidence')}`",
                    f"- Endpoint: `{finding.get('endpoint_method') or ''} "
                    f"{finding.get('endpoint_path') or finding.get('endpoint_id')}{op_str}`",
                    f"- Attack category: `{finding.get('attack_category')}`",
                    f"- Detector: `{finding.get('detector_name')}`",
                    f"- Requests: `{', '.join(finding.get('request_ids', []))}`",
                ]
            )
            evidence = finding.get("evidence", [])
            if isinstance(evidence, list) and evidence:
                lines.append("- Evidence:")
                for item in evidence:
                    if isinstance(item, dict):
                        lines.append(
                            f"  - `{item.get('evidence_type')}`: {item.get('description')}"
                        )
                        preview = item.get("observed_value_preview")
                        if preview is not None:
                            lines.append(f"    Preview: `{preview}`")
            recommendation = finding.get("recommendation")
            if recommendation:
                lines.append(f"- Recommendation: {recommendation}")
            lines.append("")
        return lines

    def _metadata_lines(self, metadata: Any) -> list[str]:
        if not isinstance(metadata, dict):
            return ["No reproducibility metadata available."]
        keys = [
            "yslfuzz_version",
            "scan_run_id",
            "target_id",
            "api_schema_id",
            "random_seed",
            "started_at",
            "finished_at",
            "generated_at",
            "dry_run",
            "attack_execution_enabled",
            "mutation_execution_enabled",
            "destructive_methods_enabled",
        ]
        return [
            f"- {key}: `{metadata.get(key)}`"
            for key in keys
            if key in metadata
        ]
