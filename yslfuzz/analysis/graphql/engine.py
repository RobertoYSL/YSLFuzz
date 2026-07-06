"""GraphQL-specific analysis engine convenience wrapper."""

from collections.abc import Sequence

from yslfuzz.analysis.finding_builder import FindingBuilder
from yslfuzz.analysis.graphql.config import GraphQLAnalysisConfig
from yslfuzz.analysis.graphql.detectors import default_graphql_detectors
from yslfuzz.models.analysis import DetectorResult, SecurityFinding
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


class GraphQLAnalysisEngine:
    """Run GraphQL detectors over executed GraphQL records."""

    def __init__(
        self,
        config: GraphQLAnalysisConfig | None = None,
        finding_builder: FindingBuilder | None = None,
    ) -> None:
        self.config = config or GraphQLAnalysisConfig()
        self.detectors = default_graphql_detectors(self.config)
        self.finding_builder = finding_builder or FindingBuilder()

    def analyze(
        self,
        records: Sequence[tuple[RequestRecord, ResponseRecord, PayloadCandidate]],
        baselines: Sequence[tuple[RequestRecord, ResponseRecord]] | None = None,
    ) -> list[DetectorResult]:
        """Return deterministic detector results for GraphQL records."""
        baseline_by_endpoint = {
            request.endpoint_id: (request, response)
            for request, response in (baselines or ())
        }
        results: list[DetectorResult] = []
        for request, response, payload in records:
            baseline_request, baseline_response = baseline_by_endpoint.get(
                request.endpoint_id,
                (request, response),
            )
            for detector in self.detectors:
                results.extend(
                    detector.detect(
                        baseline_request,
                        baseline_response,
                        request,
                        response,
                        payload,
                    )
                )
        return [result for result in results if result.matched]

    def analyze_findings(
        self,
        records: Sequence[tuple[RequestRecord, ResponseRecord, PayloadCandidate]],
        *,
        scan_run_id: str,
        baselines: Sequence[tuple[RequestRecord, ResponseRecord]] | None = None,
    ) -> tuple[list[DetectorResult], list[SecurityFinding]]:
        """Return detector results and findings for GraphQL records."""
        results = self.analyze(records, baselines=baselines)
        return results, self.finding_builder.build(results, scan_run_id=scan_run_id)


__all__ = ["GraphQLAnalysisEngine"]

