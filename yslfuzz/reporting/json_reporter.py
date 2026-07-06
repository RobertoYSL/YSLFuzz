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
from yslfuzz.models.schema import ApiSchema, Endpoint
from yslfuzz.reporting.finding_enricher import FindingEnricher
from yslfuzz.reporting.metrics import MetricsCalculator
from yslfuzz.reporting.redaction import redact_report_value
from yslfuzz.reporting.summaries import ReportSummaryBuilder


REPORT_SCHEMA_VERSION = "1.0"


class JsonReporter:
    """Build and export redacted JSON reports."""

    def __init__(
        self,
        metrics_calculator: MetricsCalculator | None = None,
        finding_enricher: FindingEnricher | None = None,
        summary_builder: ReportSummaryBuilder | None = None,
    ) -> None:
        self._metrics_calculator = metrics_calculator or MetricsCalculator()
        self._finding_enricher = finding_enricher or FindingEnricher()
        self._summary_builder = summary_builder or ReportSummaryBuilder()

    def build_report(
        self,
        scan_run: ScanRun,
        api_schema: ApiSchema | None = None,
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
        effective_endpoints = tuple(api_schema.endpoints) if api_schema is not None else tuple(endpoints)
        calculated_metrics = metrics or self._metrics_calculator.calculate(
            scan_run_id=scan_run.scan_run_id,
            endpoints=effective_endpoints,
            payloads=payloads,
            requests=requests,
            responses=responses,
            execution_results=execution_results,
            findings=findings,
        )
        report_metadata = dict(metadata or {})
        report_metadata["report_schema_version"] = REPORT_SCHEMA_VERSION
        report_metadata["redaction_enabled"] = redaction_enabled
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
        detector_metadata = self._detector_metadata(report_metadata)
        enriched_findings = self._finding_enricher.enrich(
            findings,
            api_schema=api_schema,
            endpoints=effective_endpoints,
            payloads=payloads,
            request_records=requests,
            response_records=responses,
            detector_metadata=detector_metadata,
        )
        report_metadata["enriched_findings"] = enriched_findings
        summaries = self._summary_builder.build(
            scan_run=scan_run,
            endpoints=effective_endpoints,
            api_schema=api_schema,
            payloads=payloads,
            requests=requests,
            responses=responses,
            execution_results=execution_results,
            findings=findings,
            metrics=calculated_metrics,
            target=target,
            metadata=report_metadata,
            detector_metadata=detector_metadata,
        )
        report_metadata["summaries"] = summaries
        report_metadata["severity_summary"] = summaries["severity_summary"]
        report_metadata["confidence_summary"] = summaries["confidence_summary"]
        report_metadata["attack_category_summary"] = summaries["attack_category_summary"]
        report_metadata["detector_summary"] = summaries["detector_summary"]
        report_metadata["endpoint_summary"] = summaries["endpoint_summary"]
        report_metadata["payload_summary"] = summaries["payload_summary"]
        report_metadata["analysis_summary"] = summaries["analysis_summary"]
        report_metadata["reproducibility"] = summaries["reproducibility"]
        report_metadata["redaction"] = summaries["redaction"]

        report = Report(
            scan_run_id=scan_run.scan_run_id,
            summary=ReportSummary(),
            findings=list(findings),
            metrics=calculated_metrics,
            redaction_enabled=redaction_enabled,
            metadata=report_metadata,
        )
        report.metadata["reproducibility"]["generated_at"] = report.generated_at.isoformat()
        report.metadata["summaries"]["reproducibility"]["generated_at"] = report.generated_at.isoformat()
        return report

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
        data["report_schema_version"] = REPORT_SCHEMA_VERSION
        if isinstance(metadata, dict):
            data["target_summary"] = metadata.get("target_summary")
            data["request_response_summary"] = metadata.get("request_response_summary", [])
            data["payload_generation_summary"] = metadata.get("payload_generation_summary", {})
            data["payload_summary"] = metadata.get("payload_summary", {})
            data["analysis_summary"] = metadata.get("analysis_summary", {})
            data["severity_summary"] = metadata.get("severity_summary", {})
            data["confidence_summary"] = metadata.get("confidence_summary", {})
            data["attack_category_summary"] = metadata.get("attack_category_summary", {})
            data["detector_summary"] = metadata.get("detector_summary", {})
            data["endpoint_summary"] = metadata.get("endpoint_summary", [])
            data["summaries"] = metadata.get("summaries", {})
            data["reproducibility"] = metadata.get("reproducibility", {})
            data["redaction"] = metadata.get("redaction", {})
            data["redaction_metadata"] = metadata.get("redaction", {})
            data["enriched_findings"] = metadata.get("enriched_findings", [])
            data["findings"] = metadata.get("enriched_findings", data.get("findings", []))
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

    def _detector_metadata(self, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        value = metadata.get("analysis_detectors")
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

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
            "graphql_payload_generation": metadata.get("graphql_payload_generation", {}),
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
                finding["fingerprint_hash"] = finding.get("fingerprint_hash") or metadata.get(
                    "fingerprint_hash"
                )
                finding["fingerprint"] = finding.get("fingerprint") or metadata.get("fingerprint")
            evidence = finding.get("evidence", [])
            finding["evidence_count"] = len(evidence) if isinstance(evidence, list) else 0
        return findings
