"""Finding deduplication using stable fingerprints."""

from collections.abc import Sequence

from yslfuzz.analysis.fingerprinting import FindingFingerprinter
from yslfuzz.models.analysis import Evidence, SecurityFinding
from yslfuzz.models.enums import FindingConfidence, FindingSeverity


SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

CONFIDENCE_RANK = {
    FindingConfidence.LOW: 0,
    FindingConfidence.MEDIUM: 1,
    FindingConfidence.HIGH: 2,
    FindingConfidence.CONFIRMED: 3,
}


class FindingDeduplicator:
    """Merge duplicate findings with matching stable fingerprints."""

    def __init__(self, fingerprinter: FindingFingerprinter | None = None) -> None:
        self.fingerprinter = fingerprinter or FindingFingerprinter()

    def deduplicate(self, findings: Sequence[SecurityFinding]) -> list[SecurityFinding]:
        """Return deterministically ordered deduplicated findings."""
        grouped: dict[str, SecurityFinding] = {}
        for finding in findings:
            fingerprinted = self.fingerprinter.apply(finding.model_copy(deep=True))
            fingerprint_hash = str(fingerprinted.metadata["fingerprint_hash"])
            if fingerprint_hash not in grouped:
                grouped[fingerprint_hash] = fingerprinted
                continue
            grouped[fingerprint_hash] = self._merge(grouped[fingerprint_hash], fingerprinted)
        return sorted(grouped.values(), key=self._sort_key)

    def _merge(self, existing: SecurityFinding, incoming: SecurityFinding) -> SecurityFinding:
        existing.request_ids = sorted(set(existing.request_ids).union(incoming.request_ids))
        existing.response_ids = sorted(set(existing.response_ids).union(incoming.response_ids))
        existing.evidence = self._merge_evidence(existing.evidence, incoming.evidence)
        existing.severity = max(
            [existing.severity, incoming.severity],
            key=lambda severity: SEVERITY_RANK[severity],
        )
        existing.confidence = max(
            [existing.confidence, incoming.confidence],
            key=lambda confidence: CONFIDENCE_RANK[confidence],
        )
        existing.metadata["deduplicated_count"] = int(existing.metadata.get("deduplicated_count", 1)) + 1
        return self.fingerprinter.apply(existing)

    def _merge_evidence(
        self,
        first: list[Evidence],
        second: list[Evidence],
    ) -> list[Evidence]:
        seen: set[tuple[str, str, str | None, str | None]] = set()
        merged: list[Evidence] = []
        for evidence in [*first, *second]:
            key = (
                evidence.evidence_type,
                evidence.source,
                evidence.request_id,
                evidence.response_id,
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(evidence)
        return sorted(
            merged,
            key=lambda evidence: (
                evidence.evidence_type,
                evidence.source,
                evidence.request_id or "",
                evidence.response_id or "",
            ),
        )

    def _sort_key(self, finding: SecurityFinding) -> tuple[int, str, str, str, str]:
        return (
            -SEVERITY_RANK[finding.severity],
            finding.endpoint_id,
            finding.attack_category.value,
            finding.title,
            str(finding.metadata.get("fingerprint_hash", "")),
        )
