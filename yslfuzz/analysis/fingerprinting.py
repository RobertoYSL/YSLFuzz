"""Stable finding fingerprinting."""

from hashlib import sha256
from typing import Any

from yslfuzz.models.analysis import FindingFingerprint, SecurityFinding
from yslfuzz.models.enums import AttackCategory


class FindingFingerprinter:
    """Compute deterministic fingerprints from stable finding components."""

    def fingerprint(self, finding: SecurityFinding) -> FindingFingerprint:
        """Return a stable fingerprint for a finding."""
        evidence_type = self._first_evidence_type(finding)
        detector_id = str(finding.metadata.get("detector_id") or finding.metadata.get("detector_name") or "")
        status_code_class = self._status_code_class(finding)
        normalized_title = self._normalize(finding.title)
        endpoint_identity = str(finding.metadata.get("endpoint_identity") or finding.endpoint_id)
        components: dict[str, str | None] = {
            "endpoint_identity": endpoint_identity,
            "attack_category": finding.attack_category.value,
            "detector_id": detector_id,
            "affected_parameter": finding.affected_parameter,
            "affected_location": finding.affected_location.value if finding.affected_location else None,
            "evidence_type": evidence_type,
            "status_code_class": status_code_class,
            "normalized_title": normalized_title,
        }
        encoded = "|".join(f"{key}={components[key] or ''}" for key in sorted(components))
        return FindingFingerprint(
            fingerprint_hash=sha256(encoded.encode("utf-8")).hexdigest(),
            endpoint_id=endpoint_identity,
            attack_category=AttackCategory(finding.attack_category),
            detector_id=detector_id,
            affected_parameter=finding.affected_parameter,
            affected_location=finding.affected_location,
            evidence_type=evidence_type,
            status_code_class=status_code_class,
            normalized_title=normalized_title,
            components=components,
        )

    def apply(self, finding: SecurityFinding) -> SecurityFinding:
        """Attach fingerprint metadata to a finding and return it."""
        fingerprint = self.fingerprint(finding)
        finding.metadata["fingerprint"] = fingerprint.model_dump(mode="json")
        finding.metadata["fingerprint_hash"] = fingerprint.fingerprint_hash
        return finding

    def _first_evidence_type(self, finding: SecurityFinding) -> str | None:
        evidence_types = sorted({evidence.evidence_type for evidence in finding.evidence})
        return evidence_types[0] if evidence_types else None

    def _status_code_class(self, finding: SecurityFinding) -> str | None:
        for evidence in finding.evidence:
            if evidence.evidence_type == "status_code":
                preview = evidence.observed_value_preview or ""
                for token in reversed(preview.replace("->", " ").split()):
                    if token.isdigit():
                        return f"{token[0]}xx"
        value = finding.metadata.get("status_code_class")
        return str(value) if value is not None else None

    def _normalize(self, value: Any) -> str:
        return " ".join(str(value).strip().lower().split())
