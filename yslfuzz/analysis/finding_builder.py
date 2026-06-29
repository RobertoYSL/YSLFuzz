"""Build SecurityFinding objects from detector results."""

from collections.abc import Sequence

from yslfuzz.models.analysis import DetectorResult, SecurityFinding
from yslfuzz.models.enums import AttackCategory, FindingConfidence, FindingSeverity, ParameterLocation


class FindingBuilder:
    """Aggregate matched detector results into conservative security findings."""

    def build(
        self,
        detector_results: Sequence[DetectorResult],
        scan_run_id: str,
    ) -> list[SecurityFinding]:
        """Create one finding per matched detector result."""
        findings: list[SecurityFinding] = []
        for result in detector_results:
            if not result.matched:
                continue
            target_location = result.metadata.get("target_location")
            affected_location = (
                ParameterLocation(target_location)
                if isinstance(target_location, str) and target_location in ParameterLocation
                else None
            )
            findings.append(
                SecurityFinding(
                    scan_run_id=scan_run_id,
                    endpoint_id=str(result.metadata.get("endpoint_id", "endpoint_unknown")),
                    title=self._title(result),
                    description=result.reason or "Detector matched attack response behavior.",
                    attack_category=AttackCategory(
                        result.metadata.get("attack_category", AttackCategory.INPUT_VALIDATION.value)
                    ),
                    severity=self._severity(result),
                    confidence=self._confidence(result),
                    affected_parameter=self._optional_str(result.metadata.get("target_field")),
                    affected_location=affected_location,
                    payload_id=self._optional_str(result.metadata.get("payload_id")),
                    request_ids=[result.request_id],
                    response_ids=[result.response_id] if result.response_id is not None else [],
                    evidence=list(result.evidence),
                    recommendation="Review the endpoint behavior and validate server-side handling.",
                )
            )
        return findings

    def _title(self, result: DetectorResult) -> str:
        detector_name = result.metadata.get("detector_name", "Detector")
        target = result.metadata.get("target_field")
        if target:
            return f"{detector_name} signal for {target}"
        return f"{detector_name} signal"

    def _severity(self, result: DetectorResult) -> FindingSeverity:
        return result.severity

    def _confidence(self, result: DetectorResult) -> FindingConfidence:
        return result.confidence

    def _optional_str(self, value: object) -> str | None:
        return str(value) if value is not None else None
