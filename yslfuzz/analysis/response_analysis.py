"""Response analysis orchestration."""

from collections.abc import Sequence

from yslfuzz.analysis.detectors import (
    DifferentialResponseDetector,
    ErrorMessageDetector,
    ReflectionDetector,
    ResponseDetector,
    SensitiveDataExposureDetector,
    StatusCodeAnomalyDetector,
)
from yslfuzz.analysis.finding_builder import FindingBuilder
from yslfuzz.models.analysis import DetectorResult, SecurityFinding
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


class AnalysisEngine:
    """Run response detectors and build findings from attack execution records."""

    def __init__(
        self,
        detectors: Sequence[ResponseDetector] | None = None,
        finding_builder: FindingBuilder | None = None,
    ) -> None:
        self.detectors = list(detectors or default_detectors())
        self.finding_builder = finding_builder or FindingBuilder()

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
        findings = self.finding_builder.build(detector_results, scan_run_id=scan_run_id)
        return detector_results, findings


def default_detectors() -> list[ResponseDetector]:
    """Return the default MVP response detectors."""
    return [
        StatusCodeAnomalyDetector(),
        ErrorMessageDetector(),
        ReflectionDetector(),
        DifferentialResponseDetector(),
        SensitiveDataExposureDetector(),
    ]
