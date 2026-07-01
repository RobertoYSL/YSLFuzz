"""Report-ready finding enrichment."""

from collections.abc import Sequence
from typing import Any, cast

from yslfuzz.models.analysis import Evidence, SecurityFinding
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import ApiSchema, Endpoint
from yslfuzz.reporting.redaction import redact_report_value


SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CONFIDENCE_RANK = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CONFIRMED": 3,
}


class FindingEnricher:
    """Convert SecurityFinding models into stable redacted report dictionaries."""

    def enrich(
        self,
        findings: Sequence[SecurityFinding],
        *,
        api_schema: ApiSchema | None = None,
        endpoints: Sequence[Endpoint] = (),
        payloads: Sequence[PayloadCandidate] = (),
        request_records: Sequence[RequestRecord] = (),
        response_records: Sequence[ResponseRecord] = (),
        detector_metadata: Sequence[dict[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        """Return enriched, deterministically ordered finding dictionaries."""
        endpoint_map = self._endpoint_map(api_schema, endpoints)
        payload_map = {payload.payload_id: payload for payload in payloads}
        request_map = {request.request_id: request for request in request_records}
        response_map = {response.response_id: response for response in response_records}
        detector_map = self._detector_map(detector_metadata)

        enriched = [
            self._finding_dict(
                finding,
                endpoint_map=endpoint_map,
                payload_map=payload_map,
                request_map=request_map,
                response_map=response_map,
                detector_map=detector_map,
            )
            for finding in findings
        ]
        return sorted(enriched, key=self._sort_key)

    def _finding_dict(
        self,
        finding: SecurityFinding,
        *,
        endpoint_map: dict[str, Endpoint],
        payload_map: dict[str, PayloadCandidate],
        request_map: dict[str, RequestRecord],
        response_map: dict[str, ResponseRecord],
        detector_map: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        endpoint = endpoint_map.get(finding.endpoint_id)
        payload = payload_map.get(finding.payload_id or "")
        detector_name = self._optional_str(finding.metadata.get("detector_name"))
        detector_id = self._optional_str(finding.metadata.get("detector_id"))
        detector_info = self._detector_info(detector_id, detector_name, detector_map)
        response_status_codes = [
            response_map[response_id].status_code
            for response_id in finding.response_ids
            if response_id in response_map
        ]

        value = {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description,
            "endpoint_id": finding.endpoint_id,
            "endpoint_path": endpoint.path if endpoint is not None else None,
            "endpoint_method": endpoint.method.value
            if endpoint is not None and endpoint.method is not None
            else None,
            "attack_category": finding.attack_category.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "affected_parameter": finding.affected_parameter,
            "affected_location": finding.affected_location.value
            if finding.affected_location is not None
            else None,
            "detector_id": detector_info.get("detector_id"),
            "detector_name": detector_info.get("name"),
            "detector_version": detector_info.get("version"),
            "evidence": [self._evidence_summary(evidence) for evidence in finding.evidence],
            "evidence_count": len(finding.evidence),
            "recommendation": finding.recommendation,
            "request_ids": sorted(finding.request_ids),
            "response_ids": sorted(finding.response_ids),
            "response_status_codes": sorted(response_status_codes),
            "payload_id": finding.payload_id,
            "payload_kind": payload.payload_kind.value if payload is not None else None,
            "payload_generation_strategy": payload.generation_strategy if payload is not None else None,
            "redaction": self._redaction_summary(finding.evidence),
            "fingerprint_hash": finding.metadata.get("fingerprint_hash"),
            "metadata": self._metadata(finding, request_map, payload),
        }
        return cast(dict[str, Any], redact_report_value(value))

    def _evidence_summary(self, evidence: Evidence) -> dict[str, Any]:
        return {
            "evidence_id": evidence.evidence_id,
            "evidence_type": evidence.evidence_type,
            "source": evidence.source,
            "description": evidence.description,
            "request_id": evidence.request_id,
            "response_id": evidence.response_id,
            "field_name": evidence.field_name,
            "observed_value_preview": evidence.model_dump(mode="json").get(
                "observed_value_preview"
            ),
            "redacted": evidence.redacted,
        }

    def _redaction_summary(self, evidence: Sequence[Evidence]) -> dict[str, Any]:
        return {
            "redacted": all(item.redacted for item in evidence) if evidence else True,
            "redacted_evidence_count": sum(1 for item in evidence if item.redacted),
            "total_evidence_count": len(evidence),
        }

    def _metadata(
        self,
        finding: SecurityFinding,
        request_map: dict[str, RequestRecord],
        payload: PayloadCandidate | None,
    ) -> dict[str, Any]:
        request_methods = sorted(
            {
                request_map[request_id].method.value
                for request_id in finding.request_ids
                if request_id in request_map
            }
        )
        metadata = {
            "status": finding.status.value,
            "created_at": finding.created_at.isoformat(),
            "request_methods": request_methods,
            "payload_attack_category": payload.attack_category.value
            if payload is not None and payload.attack_category is not None
            else None,
            "deduplicated_count": finding.metadata.get("deduplicated_count"),
            "detector_result_ids": finding.metadata.get("detector_result_ids", []),
            "status_code_class": finding.metadata.get("status_code_class"),
            "endpoint_identity": finding.metadata.get("endpoint_identity"),
        }
        return {key: value for key, value in metadata.items() if value not in (None, [], {})}

    def _endpoint_map(
        self,
        api_schema: ApiSchema | None,
        endpoints: Sequence[Endpoint],
    ) -> dict[str, Endpoint]:
        mapped = {endpoint.endpoint_id: endpoint for endpoint in endpoints}
        if api_schema is not None:
            mapped.update({endpoint.endpoint_id: endpoint for endpoint in api_schema.endpoints})
        return mapped

    def _detector_map(
        self,
        detector_metadata: Sequence[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        mapped: dict[str, dict[str, Any]] = {}
        for item in detector_metadata:
            for key in ("detector_id", "name"):
                value = item.get(key)
                if value is not None:
                    mapped[str(value)] = item
        return mapped

    def _detector_info(
        self,
        detector_id: str | None,
        detector_name: str | None,
        detector_map: dict[str, dict[str, Any]],
    ) -> dict[str, str | None]:
        source = detector_map.get(detector_id or "") or detector_map.get(detector_name or "") or {}
        return {
            "detector_id": self._optional_str(source.get("detector_id") or detector_id),
            "name": self._optional_str(source.get("name") or detector_name),
            "version": self._optional_str(
                source.get("version") or source.get("detector_version")
            ),
        }

    def _sort_key(self, finding: dict[str, Any]) -> tuple[int, int, str, str, str, str, str]:
        endpoint_path = str(finding.get("endpoint_path") or "")
        endpoint_method = str(finding.get("endpoint_method") or "")
        return (
            -SEVERITY_RANK.get(str(finding.get("severity")), -1),
            -CONFIDENCE_RANK.get(str(finding.get("confidence")), -1),
            endpoint_path,
            endpoint_method,
            str(finding.get("attack_category") or ""),
            str(finding.get("title") or ""),
            str(finding.get("finding_id") or ""),
        )

    def _optional_str(self, value: object) -> str | None:
        return str(value) if value is not None else None
