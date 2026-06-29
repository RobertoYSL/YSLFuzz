"""Conservative response detectors for opt-in attack analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod

from yslfuzz.models.analysis import DetectorResult, Evidence
from yslfuzz.models.enums import (
    AttackCategory,
    FindingConfidence,
    FindingSeverity,
    ParameterLocation,
)
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


class ResponseDetector(ABC):
    """Base interface for response analysis detectors."""

    detector_id: str
    name: str

    @abstractmethod
    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        """Return detector results for a baseline/attack response pair."""

    def _result(
        self,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
        *,
        confidence: FindingConfidence,
        severity: FindingSeverity,
        evidence: list[Evidence],
        reason: str,
    ) -> DetectorResult:
        result = DetectorResult(
            detector_id=self.detector_id,
            request_id=attack_request.request_id,
            response_id=attack_response.response_id,
            matched=True,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            reason=reason,
        )
        result.metadata.update(
            {
                "detector_name": self.name,
                "endpoint_id": attack_request.endpoint_id,
                "payload_id": attack_payload.payload_id,
                "attack_category": (
                    attack_payload.attack_category.value
                    if attack_payload.attack_category is not None
                    else AttackCategory.INPUT_VALIDATION.value
                ),
                "target_field": attack_payload.metadata.get("target_field"),
                "target_location": attack_payload.metadata.get("target_location"),
            }
        )
        return result

    def _evidence(
        self,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        evidence_type: str,
        description: str,
        observed_value_preview: str | None = None,
        redacted: bool = False,
    ) -> Evidence:
        return Evidence(
            evidence_type=evidence_type,
            source=self.name,
            description=description,
            request_id=attack_request.request_id,
            response_id=attack_response.response_id,
            observed_value_preview=observed_value_preview,
            redacted=redacted,
        )


class StatusCodeAnomalyDetector(ResponseDetector):
    """Detect conservative status-code anomalies between baseline and attack responses."""

    detector_id = "detector_status_code_anomaly"
    name = "StatusCodeAnomalyDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request
        if attack_response.status_code >= 500 and baseline_response.status_code < 500:
            evidence = [
                self._evidence(
                    attack_request,
                    attack_response,
                    "status_code",
                    "Attack response returned a 5xx status while baseline did not.",
                    f"{baseline_response.status_code}->{attack_response.status_code}",
                )
            ]
            return [
                self._result(
                    attack_request,
                    attack_response,
                    attack_payload,
                    confidence=FindingConfidence.MEDIUM,
                    severity=FindingSeverity.MEDIUM,
                    evidence=evidence,
                    reason="5xx status anomaly",
                )
            ]
        if baseline_response.status_code >= 400 and 200 <= attack_response.status_code < 300:
            evidence = [
                self._evidence(
                    attack_request,
                    attack_response,
                    "status_code",
                    "Attack response returned 2xx where baseline failed.",
                    f"{baseline_response.status_code}->{attack_response.status_code}",
                )
            ]
            return [
                self._result(
                    attack_request,
                    attack_response,
                    attack_payload,
                    confidence=FindingConfidence.LOW,
                    severity=FindingSeverity.LOW,
                    evidence=evidence,
                    reason="unexpected 2xx status",
                )
            ]
        return []


class ErrorMessageDetector(ResponseDetector):
    """Detect generic server-side error indicators in redacted response previews."""

    detector_id = "detector_error_message"
    name = "ErrorMessageDetector"
    _indicators = {
        "stack trace": "stack_trace_indicator",
        "traceback": "stack_trace_indicator",
        "exception": "exception_indicator",
        "sql error": "database_error_indicator",
        "database error": "database_error_indicator",
        "django": "framework_error_indicator",
        "flask": "framework_error_indicator",
        "express error": "framework_error_indicator",
    }

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        preview = (attack_response.body_preview or "").lower()
        for indicator, evidence_type in self._indicators.items():
            if indicator in preview:
                evidence = [
                    self._evidence(
                        attack_request,
                        attack_response,
                        evidence_type,
                        "Generic server-side error indicator appeared in response preview.",
                        indicator,
                    )
                ]
                return [
                    self._result(
                        attack_request,
                        attack_response,
                        attack_payload,
                        confidence=FindingConfidence.LOW,
                        severity=FindingSeverity.MEDIUM,
                        evidence=evidence,
                        reason="generic server error indicator",
                    )
                ]
        return []


class ReflectionDetector(ResponseDetector):
    """Detect reflected inert YSLFuzz markers in response previews."""

    detector_id = "detector_reflection"
    name = "ReflectionDetector"
    _markers = (
        "yslfuzz_probe",
        "yslfuzz_sqli_probe",
        "yslfuzz_xss_probe",
        "yslfuzz_ssrf_probe",
        "yslfuzz_cmd_probe",
    )

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        preview = attack_response.body_preview or ""
        for marker in self._markers:
            if marker in preview:
                evidence = [
                    self._evidence(
                        attack_request,
                        attack_response,
                        "marker_reflection",
                        "Inert YSLFuzz marker appeared in response preview.",
                        marker,
                    )
                ]
                return [
                    self._result(
                        attack_request,
                        attack_response,
                        attack_payload,
                        confidence=FindingConfidence.LOW,
                        severity=FindingSeverity.LOW,
                        evidence=evidence,
                        reason="marker reflected",
                    )
                ]
        return []


class DifferentialResponseDetector(ResponseDetector):
    """Detect conservative response differences between baseline and attack responses."""

    detector_id = "detector_differential_response"
    name = "DifferentialResponseDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request
        reasons: list[str] = []
        if baseline_response.status_code != attack_response.status_code:
            reasons.append("status code changed")
        if self._size_changed(baseline_response.body_size_bytes, attack_response.body_size_bytes):
            reasons.append("response size changed significantly")
        if (
            baseline_response.body_hash is not None
            and attack_response.body_hash is not None
            and baseline_response.body_hash != attack_response.body_hash
        ):
            reasons.append("body hash changed")
        if self._time_changed(
            baseline_response.response_time_ms,
            attack_response.response_time_ms,
        ):
            reasons.append("response time changed significantly")

        if not reasons:
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "differential_response",
                "; ".join(reasons),
                ", ".join(reasons),
            )
        ]
        return [
            self._result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.LOW,
                severity=FindingSeverity.LOW,
                evidence=evidence,
                reason="differential response",
            )
        ]

    def _size_changed(self, baseline_size: int, attack_size: int) -> bool:
        if baseline_size == attack_size:
            return False
        if baseline_size == 0:
            return attack_size >= 256
        return abs(attack_size - baseline_size) / baseline_size >= 0.5

    def _time_changed(self, baseline_time_ms: float, attack_time_ms: float) -> bool:
        if baseline_time_ms <= 0:
            return False
        return attack_time_ms >= baseline_time_ms * 3 and attack_time_ms - baseline_time_ms >= 250.0


class SensitiveDataExposureDetector(ResponseDetector):
    """Detect clearly sensitive-looking keys in response previews with redacted evidence."""

    detector_id = "detector_sensitive_data_exposure"
    name = "SensitiveDataExposureDetector"
    _keys = ("password", "token", "access_token", "refresh_token", "api_key", "secret", "jwt")

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        preview = (attack_response.body_preview or "").lower()
        for key in self._keys:
            if key in preview:
                evidence = [
                    Evidence(
                        evidence_type="sensitive_key_exposure",
                        source=self.name,
                        description="Sensitive-looking key appeared in response preview.",
                        request_id=attack_request.request_id,
                        response_id=attack_response.response_id,
                        field_name=key,
                        observed_value_preview=key,
                        redacted=True,
                    )
                ]
                result = self._result(
                    attack_request,
                    attack_response,
                    attack_payload,
                    confidence=FindingConfidence.HIGH,
                    severity=FindingSeverity.HIGH,
                    evidence=evidence,
                    reason="sensitive data exposure indicator",
                )
                result.metadata["affected_location"] = ParameterLocation.BODY.value
                return [result]
        return []
