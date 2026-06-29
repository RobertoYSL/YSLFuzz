"""Scan metrics calculation."""

from collections.abc import Sequence

from yslfuzz.models.analysis import SecurityFinding
from yslfuzz.models.enums import ExecutionStatus, PayloadKind
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.reporting import ScanMetrics
from yslfuzz.models.schema import Endpoint


class MetricsCalculator:
    """Calculate MVP scan metrics from internal execution data."""

    def calculate(
        self,
        scan_run_id: str,
        endpoints: Sequence[Endpoint] = (),
        payloads: Sequence[PayloadCandidate] = (),
        requests: Sequence[RequestRecord] = (),
        responses: Sequence[ResponseRecord] = (),
        execution_results: Sequence[ExecutionResult] = (),
        findings: Sequence[SecurityFinding] = (),
    ) -> ScanMetrics:
        """Calculate ScanMetrics using documented MVP formulas."""
        total_endpoints = len(endpoints)
        tested_endpoint_ids = {request.endpoint_id for request in requests}
        payloads_generated = len(payloads)
        valid_payloads_generated = sum(
            1 for payload in payloads if payload.payload_kind == PayloadKind.VALID
        )
        attack_payloads_generated = sum(
            1 for payload in payloads if payload.payload_kind == PayloadKind.ATTACK
        )
        successful_requests = self._successful_requests(execution_results, responses)
        failed_requests = self._failed_requests(execution_results)
        timeout_requests = sum(
            1
            for result in execution_results
            if result.status == ExecutionStatus.FAILED and result.error_type == "timeout"
        )

        return ScanMetrics(
            scan_run_id=scan_run_id,
            total_endpoints=total_endpoints,
            tested_endpoints=len(tested_endpoint_ids),
            total_requests=len(requests),
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            timeout_requests=timeout_requests,
            payloads_generated=payloads_generated,
            valid_payloads_generated=valid_payloads_generated,
            attack_payloads_generated=attack_payloads_generated,
            findings_total=len(findings),
            findings_by_severity=self._findings_by_severity(findings),
            average_response_time_ms=self._average_response_time(responses),
            endpoint_coverage=self._rate(len(tested_endpoint_ids), total_endpoints),
            payload_validity_rate=self._rate(valid_payloads_generated, payloads_generated),
        )

    def _successful_requests(
        self,
        execution_results: Sequence[ExecutionResult],
        responses: Sequence[ResponseRecord],
    ) -> int:
        if execution_results:
            return sum(1 for result in execution_results if result.status == ExecutionStatus.COMPLETED)
        return sum(1 for response in responses if 200 <= response.status_code < 400)

    def _failed_requests(self, execution_results: Sequence[ExecutionResult]) -> int:
        return sum(1 for result in execution_results if result.status == ExecutionStatus.FAILED)

    def _findings_by_severity(self, findings: Sequence[SecurityFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _average_response_time(self, responses: Sequence[ResponseRecord]) -> float:
        if not responses:
            return 0.0
        total = sum(response.response_time_ms for response in responses)
        return round(total / len(responses), 3)

    def _rate(self, numerator: int, denominator: int) -> float:
        if denominator == 0:
            return 0.0
        return round(numerator / denominator, 6)
