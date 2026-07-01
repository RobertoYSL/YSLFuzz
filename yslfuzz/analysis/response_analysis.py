"""Response analysis orchestration."""

from collections.abc import Sequence

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.analysis.detectors import ResponseDetector
from yslfuzz.analysis.finding_builder import FindingBuilder
from yslfuzz.analysis.registry import DetectorRegistry
from yslfuzz.models.analysis import DetectorResult, SecurityFinding
from yslfuzz.models.enums import FindingConfidence, FindingSeverity
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


CONFIDENCE_RANK = {
    FindingConfidence.LOW: 0,
    FindingConfidence.MEDIUM: 1,
    FindingConfidence.HIGH: 2,
    FindingConfidence.CONFIRMED: 3,
}


class AnalysisEngine:
    """Run response detectors and build findings from execution records."""

    def __init__(
        self,
        config: AnalysisConfig | None = None,
        detectors: Sequence[ResponseDetector] | None = None,
        finding_builder: FindingBuilder | None = None,
    ) -> None:
        self.config = config or AnalysisConfig()
        self.registry = DetectorRegistry(detectors=detectors, config=self.config)
        self.detectors = self.registry.detectors()
        self.finding_builder = finding_builder or FindingBuilder()
        self.last_total_detector_results = 0
        self.last_total_raw_findings = 0
        self.last_total_deduplicated_findings = 0

    def analyze(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_records: Sequence[tuple[RequestRecord, ResponseRecord, PayloadCandidate]],
        scan_run_id: str,
    ) -> tuple[list[DetectorResult], list[SecurityFinding]]:
        """Analyze attack responses against a baseline response."""
        detector_results: list[DetectorResult] = []
        for attack_request, attack_response, attack_payload in attack_records:
            for detector in self.detectors:
                detector_results.extend(
                    detector.detect(
                        baseline_request,
                        baseline_response,
                        attack_request,
                        attack_response,
                        attack_payload,
                    )
                )
        return self._finalize(detector_results, scan_run_id)

    def analyze_records(
        self,
        baseline_records: Sequence[tuple[RequestRecord, ResponseRecord]],
        test_records: Sequence[tuple[RequestRecord, ResponseRecord, PayloadCandidate]],
        scan_run_id: str,
    ) -> tuple[list[DetectorResult], list[SecurityFinding]]:
        """Analyze multiple test records using the first baseline for each endpoint."""
        baselines_by_endpoint = {
            request.endpoint_id: (request, response)
            for request, response in baseline_records
        }
        detector_results: list[DetectorResult] = []
        for attack_request, attack_response, attack_payload in test_records:
            baseline = baselines_by_endpoint.get(attack_request.endpoint_id)
            if baseline is None:
                continue
            baseline_request, baseline_response = baseline
            for detector in self.detectors:
                detector_results.extend(
                    detector.detect(
                        baseline_request,
                        baseline_response,
                        attack_request,
                        attack_response,
                        attack_payload,
                    )
                )
        return self._finalize(detector_results, scan_run_id)

    def detector_metadata(self) -> list[dict[str, str]]:
        """Return stable metadata for enabled detectors."""
        return self.registry.metadata()

    def analysis_summary(self) -> dict[str, object]:
        """Return non-sensitive analysis configuration and detector metadata."""
        return {
            "config": self.config.summary(),
            "detectors": self.detector_metadata(),
            "total_detector_results": self.last_total_detector_results,
            "total_raw_findings": self.last_total_raw_findings,
            "total_deduplicated_findings": self.last_total_deduplicated_findings,
        }

    def _finalize(
        self,
        detector_results: Sequence[DetectorResult],
        scan_run_id: str,
    ) -> tuple[list[DetectorResult], list[SecurityFinding]]:
        filtered_results = [result for result in detector_results if self._include_result(result)]
        findings = self.finding_builder.build(filtered_results, scan_run_id=scan_run_id)
        self.last_total_detector_results = len(filtered_results)
        self.last_total_raw_findings = self.finding_builder.last_raw_finding_count
        self.last_total_deduplicated_findings = (
            self.finding_builder.last_deduplicated_finding_count
        )
        return filtered_results, findings

    def _include_result(self, result: DetectorResult) -> bool:
        if not self.config.include_info_findings and result.severity == FindingSeverity.INFO:
            return False
        if self.config.minimum_confidence is None:
            return True
        return (
            CONFIDENCE_RANK[result.confidence]
            >= CONFIDENCE_RANK[self.config.minimum_confidence]
        )


def default_detectors(config: AnalysisConfig | None = None) -> list[ResponseDetector]:
    """Return default MVP response detectors in deterministic order."""
    from yslfuzz.analysis.registry import default_detectors as registry_default_detectors

    return registry_default_detectors(config)
