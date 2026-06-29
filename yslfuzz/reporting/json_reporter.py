"""JSON report generation."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from yslfuzz.models.analysis import SecurityFinding
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord, ScanRun
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import Target
from yslfuzz.models.reporting import Report, ReportSummary, ScanMetrics
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting.metrics import MetricsCalculator
from yslfuzz.reporting.redaction import redact_report_value


class JsonReporter:
    """Build and export redacted JSON reports."""

    def __init__(self, metrics_calculator: MetricsCalculator | None = None) -> None:
        self._metrics_calculator = metrics_calculator or MetricsCalculator()

    def build_report(
        self,
        scan_run: ScanRun,
        endpoints: Sequence[Endpoint] = (),
        payloads: Sequence[PayloadCandidate] = (),
        requests: Sequence[RequestRecord] = (),
        responses: Sequence[ResponseRecord] = (),
        execution_results: Sequence[ExecutionResult] = (),
        findings: Sequence[SecurityFinding] = (),
        target: Target | None = None,
        redaction_enabled: bool = True,
        metadata: dict[str, Any] | None = None,
        metrics: ScanMetrics | None = None,
    ) -> Report:
        """Build a Report model with calculated metrics and report metadata."""
        calculated_metrics = metrics or self._metrics_calculator.calculate(
            scan_run_id=scan_run.scan_run_id,
            endpoints=endpoints,
            payloads=payloads,
            requests=requests,
            responses=responses,
            execution_results=execution_results,
            findings=findings,
        )
        report_metadata = dict(metadata or {})
        report_metadata["target_summary"] = self._target_summary(target)
        report_metadata["request_response_summary"] = self._request_response_summary(
            requests,
            responses,
            execution_results,
        )

        return Report(
            scan_run_id=scan_run.scan_run_id,
            summary=ReportSummary(),
            findings=list(findings),
            metrics=calculated_metrics,
            redaction_enabled=redaction_enabled,
            metadata=report_metadata,
        )

    def to_json(self, report: Report, indent: int | None = 2) -> str:
        """Serialize a report to a redacted JSON string."""
        return json.dumps(self.to_dict(report), indent=indent, sort_keys=True, default=str)

    def write_json(self, report: Report, path: str | Path, indent: int | None = 2) -> Path:
        """Write a redacted JSON report and return the written path."""
        output_path = Path(path)
        output_path.write_text(self.to_json(report, indent=indent), encoding="utf-8")
        return output_path

    def to_dict(self, report: Report) -> dict[str, Any]:
        """Convert a report to the JSON export dictionary."""
        data = report.model_dump(mode="json")
        metadata = data.get("metadata", {})
        if isinstance(metadata, dict):
            data["target_summary"] = metadata.get("target_summary")
            data["request_response_summary"] = metadata.get("request_response_summary", [])
        return cast(dict[str, Any], redact_report_value(data))

    def _target_summary(self, target: Target | None) -> dict[str, Any] | None:
        if target is None:
            return None
        return {
            "target_id": target.target_id,
            "name": target.name,
            "base_url": target.base_url,
            "api_style": target.api_style.value,
            "protocol": target.protocol.value,
        }

    def _request_response_summary(
        self,
        requests: Sequence[RequestRecord],
        responses: Sequence[ResponseRecord],
        execution_results: Sequence[ExecutionResult],
    ) -> list[dict[str, Any]]:
        responses_by_request_id = {response.request_id: response for response in responses}
        results_by_request_id = {result.request_id: result for result in execution_results}
        summaries: list[dict[str, Any]] = []

        for request in requests:
            response = responses_by_request_id.get(request.request_id)
            result = results_by_request_id.get(request.request_id)
            summaries.append(
                {
                    "request": request.model_dump(mode="json"),
                    "response": response.model_dump(mode="json") if response is not None else None,
                    "execution_result": result.model_dump(mode="json") if result is not None else None,
                }
            )
        return summaries
