"""JSON report generation."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from yslfuzz import __version__
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
        report_metadata["payload_generation_summary"] = self._payload_generation_summary(
            calculated_metrics,
            report_metadata,
        )
        report_metadata["analysis_summary"] = self._analysis_summary(
            findings,
            report_metadata,
            calculated_metrics,
        )
        report_metadata["reproducibility"] = self._reproducibility_metadata(
            scan_run=scan_run,
            payloads=payloads,
            findings=findings,
            target=target,
            metadata=report_metadata,
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
            data["payload_generation_summary"] = metadata.get("payload_generation_summary", {})
            data["analysis_summary"] = metadata.get("analysis_summary", {})
            data["reproducibility"] = metadata.get("reproducibility", {})
        data["findings"] = self._finding_summaries(data.get("findings", []))
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

    def _reproducibility_metadata(
        self,
        scan_run: ScanRun,
        payloads: Sequence[PayloadCandidate],
        findings: Sequence[SecurityFinding],
        target: Target | None,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        attack_categories = sorted(
            {
                payload.attack_category.value
                for payload in payloads
                if payload.attack_category is not None
            }
        )
        detector_names = sorted(
            {
                str(finding.metadata.get("detector_name"))
                for finding in findings
                if finding.metadata.get("detector_name") is not None
            }
        )
        seeds = sorted({payload.seed for payload in payloads})
        return {
            "yslfuzz_version": __version__,
            "scan_run_id": scan_run.scan_run_id,
            "random_seed": seeds[0] if len(seeds) == 1 else seeds,
            "api_schema_id": scan_run.api_schema_id,
            "target_id": target.target_id if target is not None else scan_run.target_id,
            "timestamp": scan_run.started_at.isoformat(),
            "enabled_attack_categories": metadata.get("enabled_attack_categories", attack_categories),
            "attack_execution_enabled": bool(metadata.get("attack_execution_enabled", False)),
            "mutation_execution_enabled": bool(metadata.get("mutation_execution_enabled", False)),
            "detectors": [
                {"name": name, "version": self._detector_version(name, findings)}
                for name in detector_names
            ],
            "total_detector_results": int(metadata.get("total_detector_results", 0)),
            "total_raw_findings": int(metadata.get("total_raw_findings", len(findings))),
            "total_deduplicated_findings": int(
                metadata.get("total_deduplicated_findings", len(findings))
            ),
        }

    def _analysis_summary(
        self,
        findings: Sequence[SecurityFinding],
        metadata: dict[str, Any],
        metrics: ScanMetrics,
    ) -> dict[str, Any]:
        by_detector: dict[str, int] = {}
        detectors: dict[str, dict[str, str | None]] = {}
        for finding in findings:
            detector_name = finding.metadata.get("detector_name")
            if detector_name is None:
                continue
            name = str(detector_name)
            by_detector[name] = by_detector.get(name, 0) + 1
            detectors[name] = {
                "detector_id": self._optional_str(finding.metadata.get("detector_id")),
                "name": name,
                "version": self._optional_str(finding.metadata.get("detector_version")),
            }

        configured_detectors = metadata.get("analysis_detectors")
        if isinstance(configured_detectors, list):
            for item in configured_detectors:
                if not isinstance(item, dict) or item.get("name") is None:
                    continue
                name = str(item["name"])
                detectors.setdefault(
                    name,
                    {
                        "detector_id": self._optional_str(item.get("detector_id")),
                        "name": name,
                        "version": self._optional_str(item.get("version")),
                    },
                )

        return {
            "detectors": [detectors[name] for name in sorted(detectors)],
            "detector_result_count": int(metadata.get("total_detector_results", 0)),
            "finding_count_by_detector": {
                name: by_detector[name]
                for name in sorted(by_detector)
            },
            "finding_count_by_severity": metrics.findings_by_severity,
            "analysis_configuration": metadata.get("analysis_config", {}),
        }

    def _payload_generation_summary(
        self,
        metrics: ScanMetrics,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "generated_by_kind": {
                "VALID": metrics.valid_payloads_generated,
                "BOUNDARY": metrics.boundary_payloads_generated,
                "INVALID": metrics.invalid_payloads_generated,
                "MUTATED": metrics.mutated_payloads_generated,
                "ATTACK": metrics.attack_payloads_generated,
            },
            "executed_by_kind": {
                "VALID": metrics.valid_payloads_executed,
                "BOUNDARY": metrics.boundary_payloads_executed,
                "INVALID": metrics.invalid_payloads_executed,
                "MUTATED": metrics.mutated_payloads_executed,
                "ATTACK": metrics.attack_payloads_executed,
            },
            "skipped_by_kind": metrics.skipped_payloads_by_kind,
            "skipped_payloads_not_authorized": metrics.skipped_payloads_not_authorized,
            "mutation_config": metadata.get("mutation_config", {}),
            "mutation_execution_enabled": bool(metadata.get("mutation_execution_enabled", False)),
            "attack_execution_enabled": bool(metadata.get("attack_execution_enabled", False)),
            "random_seed": metadata.get("random_seed"),
            "max_mutations_per_payload": metadata.get("max_mutations_per_payload"),
            "max_mutations_per_field": metadata.get("max_mutations_per_field"),
        }

    def _detector_version(
        self,
        detector_name: str,
        findings: Sequence[SecurityFinding],
    ) -> str | None:
        for finding in findings:
            if finding.metadata.get("detector_name") == detector_name:
                version = finding.metadata.get("detector_version")
                return str(version) if version is not None else "0.1.0"
        return "0.1.0"

    def _optional_str(self, value: object) -> str | None:
        return str(value) if value is not None else None

    def _finding_summaries(self, findings: Any) -> Any:
        if not isinstance(findings, list):
            return findings
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            metadata = finding.get("metadata", {})
            if isinstance(metadata, dict):
                finding["fingerprint_hash"] = metadata.get("fingerprint_hash")
                finding["fingerprint"] = metadata.get("fingerprint")
            evidence = finding.get("evidence", [])
            finding["evidence_count"] = len(evidence) if isinstance(evidence, list) else 0
        return findings
