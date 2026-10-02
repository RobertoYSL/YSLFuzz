"""Deterministic report summary builders."""

from collections.abc import Sequence
from datetime import datetime
from typing import Any, cast

from yslfuzz import __version__
from yslfuzz.models.analysis import SecurityFinding
from yslfuzz.models.enums import AttackCategory, FindingConfidence, FindingSeverity, PayloadKind
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord, ScanRun
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.project import Target
from yslfuzz.models.reporting import ScanMetrics
from yslfuzz.models.schema import ApiSchema, Endpoint
from yslfuzz.reporting.redaction import redact_report_value


SEVERITY_ORDER = [
    FindingSeverity.INFO,
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
]
CONFIDENCE_ORDER = [
    FindingConfidence.LOW,
    FindingConfidence.MEDIUM,
    FindingConfidence.HIGH,
    FindingConfidence.CONFIRMED,
]
PAYLOAD_KIND_ORDER = [
    PayloadKind.VALID,
    PayloadKind.BOUNDARY,
    PayloadKind.INVALID,
    PayloadKind.MUTATED,
    PayloadKind.ATTACK,
    PayloadKind.CONTROL,
]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
CONFIDENCE_RANK = {confidence: index for index, confidence in enumerate(CONFIDENCE_ORDER)}


class ReportSummaryBuilder:
    """Build stable report-level summaries for findings, endpoints, and payloads."""

    def build(
        self,
        *,
        scan_run: ScanRun,
        endpoints: Sequence[Endpoint] = (),
        api_schema: ApiSchema | None = None,
        payloads: Sequence[PayloadCandidate] = (),
        requests: Sequence[RequestRecord] = (),
        responses: Sequence[ResponseRecord] = (),
        execution_results: Sequence[ExecutionResult] = (),
        findings: Sequence[SecurityFinding] = (),
        metrics: ScanMetrics,
        target: Target | None = None,
        metadata: dict[str, Any] | None = None,
        detector_metadata: Sequence[dict[str, Any]] = (),
        generated_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Return all structured summaries used by JSON and Markdown reports."""
        del responses, execution_results
        report_metadata = metadata or {}
        effective_endpoints = self._endpoints(api_schema, endpoints)
        value = {
            "severity_summary": self.severity_summary(findings),
            "confidence_summary": self.confidence_summary(findings),
            "attack_category_summary": self.attack_category_summary(findings),
            "detector_summary": self.detector_summary(findings, detector_metadata),
            "endpoint_summary": self.endpoint_summary(effective_endpoints, requests, findings),
            "payload_summary": self.payload_summary(payloads, requests, metrics),
            "analysis_summary": self.analysis_summary(
                findings,
                metadata=report_metadata,
                metrics=metrics,
                detector_metadata=detector_metadata,
            ),
            "reproducibility": self.reproducibility_metadata(
                scan_run=scan_run,
                payloads=payloads,
                findings=findings,
                target=target,
                metadata=report_metadata,
                generated_at=generated_at,
                api_schema=api_schema,
            ),
            "redaction": {
                "enabled": bool(report_metadata.get("redaction_enabled", True)),
                "body_storage": "preview_only",
                "sensitive_values_redacted": True,
            },
        }
        return cast(dict[str, Any], redact_report_value(value))

    def severity_summary(self, findings: Sequence[SecurityFinding]) -> dict[str, int]:
        """Count findings by severity, including zero-count severities."""
        return {
            severity.value: sum(1 for finding in findings if finding.severity == severity)
            for severity in SEVERITY_ORDER
        }

    def confidence_summary(self, findings: Sequence[SecurityFinding]) -> dict[str, int]:
        """Count findings by confidence, including zero-count confidence levels."""
        return {
            confidence.value: sum(1 for finding in findings if finding.confidence == confidence)
            for confidence in CONFIDENCE_ORDER
        }

    def attack_category_summary(self, findings: Sequence[SecurityFinding]) -> dict[str, int]:
        """Count findings by attack category with deterministic key ordering."""
        counts = {
            category.value: sum(1 for finding in findings if finding.attack_category == category)
            for category in AttackCategory
        }
        return {key: counts[key] for key in sorted(counts)}

    def detector_summary(
        self,
        findings: Sequence[SecurityFinding],
        detector_metadata: Sequence[dict[str, Any]] = (),
    ) -> dict[str, dict[str, Any]]:
        """Count findings by detector name and include known detector versions."""
        detectors: dict[str, dict[str, Any]] = {}
        for item in detector_metadata:
            name = item.get("name")
            if name is None:
                continue
            detectors[str(name)] = {
                "detector_id": self._optional_str(item.get("detector_id")),
                "version": self._optional_str(item.get("version")),
                "finding_count": 0,
            }
        for finding in findings:
            name = self._detector_name(finding)
            entry = detectors.setdefault(
                name,
                {
                    "detector_id": self._optional_str(finding.metadata.get("detector_id")),
                    "version": self._optional_str(finding.metadata.get("detector_version")),
                    "finding_count": 0,
                },
            )
            entry["finding_count"] = int(entry["finding_count"]) + 1
        return {name: detectors[name] for name in sorted(detectors)}

    def endpoint_summary(
        self,
        endpoints: Sequence[Endpoint],
        requests: Sequence[RequestRecord],
        findings: Sequence[SecurityFinding],
    ) -> list[dict[str, Any]]:
        """Build per-endpoint testing and finding summaries."""
        request_count_by_endpoint: dict[str, int] = {}
        for request in requests:
            request_count_by_endpoint[request.endpoint_id] = (
                request_count_by_endpoint.get(request.endpoint_id, 0) + 1
            )
        findings_by_endpoint: dict[str, list[SecurityFinding]] = {}
        for finding in findings:
            findings_by_endpoint.setdefault(finding.endpoint_id, []).append(finding)

        summaries = [
            {
                "endpoint_id": endpoint.endpoint_id,
                "method": endpoint.method.value if endpoint.method is not None else None,
                "path": endpoint.path,
                "graphql_operation_type": getattr(endpoint, "graphql_operation_type", None),
                "graphql_operation_name": getattr(endpoint, "graphql_operation_name", None),
                "tested": request_count_by_endpoint.get(endpoint.endpoint_id, 0) > 0,
                "request_count": request_count_by_endpoint.get(endpoint.endpoint_id, 0),
                "finding_count": len(findings_by_endpoint.get(endpoint.endpoint_id, [])),
                "highest_severity": self._highest_severity(
                    findings_by_endpoint.get(endpoint.endpoint_id, [])
                ),
                "highest_confidence": self._highest_confidence(
                    findings_by_endpoint.get(endpoint.endpoint_id, [])
                ),
            }
            for endpoint in endpoints
        ]
        return sorted(summaries, key=lambda item: (str(item["path"] or ""), str(item["method"] or "")))

    def payload_summary(
        self,
        payloads: Sequence[PayloadCandidate],
        requests: Sequence[RequestRecord],
        metrics: ScanMetrics,
    ) -> dict[str, Any]:
        """Build generated, executed, and skipped payload summaries."""
        del metrics
        generated = {kind.value: 0 for kind in PAYLOAD_KIND_ORDER}
        for payload in payloads:
            generated[payload.payload_kind.value] = generated.get(payload.payload_kind.value, 0) + 1

        payload_kind_by_id = {payload.payload_id: payload.payload_kind.value for payload in payloads}
        executed = {kind.value: 0 for kind in PAYLOAD_KIND_ORDER}
        for request in requests:
            if request.payload_id is None:
                continue
            kind = payload_kind_by_id.get(request.payload_id)
            if kind is not None:
                executed[kind] = executed.get(kind, 0) + 1

        skipped = {
            kind: max(0, generated.get(kind, 0) - executed.get(kind, 0))
            for kind in sorted(generated)
        }
        return {
            "generated_by_kind": {kind: generated[kind] for kind in sorted(generated)},
            "executed_by_kind": {kind: executed[kind] for kind in sorted(executed)},
            "skipped_by_kind": {
                kind: skipped[kind]
                for kind in sorted(skipped)
                if skipped[kind] > 0
            },
            "attack_payloads_generated": generated.get(PayloadKind.ATTACK.value, 0),
            "attack_payloads_executed": executed.get(PayloadKind.ATTACK.value, 0),
            "mutation_payloads_generated": generated.get(PayloadKind.MUTATED.value, 0),
            "mutation_payloads_executed": executed.get(PayloadKind.MUTATED.value, 0),
        }

    def analysis_summary(
        self,
        findings: Sequence[SecurityFinding],
        *,
        metadata: dict[str, Any],
        metrics: ScanMetrics,
        detector_metadata: Sequence[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        """Build detector and analysis configuration summary."""
        config = metadata.get("analysis_config", {})
        detector_summary = self.detector_summary(findings, detector_metadata)
        return {
            "enabled_detectors": config.get("enabled_detectors")
            if isinstance(config, dict)
            else None,
            "disabled_detectors": config.get("disabled_detectors", [])
            if isinstance(config, dict)
            else [],
            "detectors": [
                {
                    "detector_id": value.get("detector_id"),
                    "name": name,
                    "version": value.get("version"),
                }
                for name, value in detector_summary.items()
            ],
            "detector_result_count": int(metadata.get("total_detector_results", 0)),
            "total_findings": metrics.findings_total,
            "finding_count_by_detector": {
                name: int(value["finding_count"])
                for name, value in detector_summary.items()
                if int(value["finding_count"]) > 0
            },
            "finding_count_by_severity": metrics.findings_by_severity,
            "analysis_configuration": config,
        }

    def reproducibility_metadata(
        self,
        *,
        scan_run: ScanRun,
        payloads: Sequence[PayloadCandidate],
        findings: Sequence[SecurityFinding],
        target: Target | None,
        metadata: dict[str, Any],
        generated_at: datetime | None,
        api_schema: ApiSchema | None,
    ) -> dict[str, Any]:
        """Build non-sensitive reproducibility metadata."""
        seeds = sorted({payload.seed for payload in payloads})
        source = api_schema.created_from[0] if api_schema is not None and api_schema.created_from else None
        return {
            "yslfuzz_version": __version__,
            "scan_run_id": scan_run.scan_run_id,
            "target_id": target.target_id if target is not None else scan_run.target_id,
            "api_schema_id": api_schema.api_schema_id if api_schema is not None else scan_run.api_schema_id,
            "random_seed": seeds[0] if len(seeds) == 1 else seeds,
            "started_at": scan_run.started_at.isoformat(),
            "timestamp": scan_run.started_at.isoformat(),
            "finished_at": scan_run.finished_at.isoformat()
            if scan_run.finished_at is not None
            else None,
            "generated_at": generated_at.isoformat() if generated_at is not None else None,
            "parser": {
                "source_type": source.source_type if source is not None else None,
                "parser_version": source.parser_version if source is not None else None,
            },
            "enabled_payload_modes": self._enabled_payload_modes(payloads, metadata),
            "attack_execution_enabled": bool(metadata.get("attack_execution_enabled", False)),
            "mutation_execution_enabled": bool(metadata.get("mutation_execution_enabled", False)),
            "destructive_methods_enabled": bool(metadata.get("destructive_methods_enabled", False)),
            "dry_run": bool(metadata.get("dry_run", False)),
            "enabled_attack_categories": metadata.get(
                "enabled_attack_categories",
                sorted(
                    {
                        payload.attack_category.value
                        for payload in payloads
                        if payload.attack_category is not None
                    }
                ),
            ),
            "detectors": [
                {
                    "name": name,
                    "version": value.get("version") or "0.1.0",
                }
                for name, value in self.detector_summary(findings).items()
            ],
            "total_detector_results": int(metadata.get("total_detector_results", 0)),
            "total_raw_findings": int(metadata.get("total_raw_findings", len(findings))),
            "total_deduplicated_findings": int(
                metadata.get("total_deduplicated_findings", len(findings))
            ),
        }

    def _enabled_payload_modes(
        self,
        payloads: Sequence[PayloadCandidate],
        metadata: dict[str, Any],
    ) -> list[str]:
        modes = sorted({payload.payload_kind.value for payload in payloads})
        configured = metadata.get("enabled_payload_modes")
        if isinstance(configured, list):
            return sorted(str(item) for item in configured)
        return modes

    def _endpoints(
        self,
        api_schema: ApiSchema | None,
        endpoints: Sequence[Endpoint],
    ) -> list[Endpoint]:
        mapped = {endpoint.endpoint_id: endpoint for endpoint in endpoints}
        if api_schema is not None:
            mapped.update({endpoint.endpoint_id: endpoint for endpoint in api_schema.endpoints})
        return list(mapped.values())

    def _highest_severity(self, findings: Sequence[SecurityFinding]) -> str | None:
        if not findings:
            return None
        return max(findings, key=lambda finding: SEVERITY_RANK[finding.severity]).severity.value

    def _highest_confidence(self, findings: Sequence[SecurityFinding]) -> str | None:
        if not findings:
            return None
        return max(findings, key=lambda finding: CONFIDENCE_RANK[finding.confidence]).confidence.value

    def _detector_name(self, finding: SecurityFinding) -> str:
        value = finding.metadata.get("detector_name") or finding.metadata.get("detector_id")
        return str(value) if value is not None else "unknown"

    def _optional_str(self, value: object) -> str | None:
        return str(value) if value is not None else None
