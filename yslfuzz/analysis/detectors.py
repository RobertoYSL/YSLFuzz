"""Conservative response detectors for opt-in attack analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.models.analysis import DetectorResult, Evidence
from yslfuzz.models.enums import (
    AttackCategory,
    FindingConfidence,
    FindingSeverity,
    ParameterLocation,
    PayloadKind,
)
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


class ResponseDetector(ABC):
    """Base interface for response analysis detectors."""

    detector_id: str
    name: str
    version = "0.1.0"

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        self.config = config or AnalysisConfig()

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
        attack_category = self._attack_category(attack_payload)
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
                "detector_version": self.version,
                "endpoint_id": attack_request.endpoint_id,
                "endpoint_identity": (
                    f"{attack_request.method.value} {urlparse(attack_request.url).path or '/'}"
                ),
                "payload_id": attack_payload.payload_id,
                "payload_kind": attack_payload.payload_kind.value,
                "attack_category": attack_category.value,
                "target_field": self._metadata_value(attack_payload.metadata, "target_field"),
                "target_location": self._metadata_value(attack_payload.metadata, "target_location"),
                "status_code": attack_response.status_code,
                "status_code_class": f"{str(attack_response.status_code)[0]}xx",
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
        *,
        redacted: bool = True,
        field_name: str | None = None,
    ) -> Evidence:
        return Evidence(
            evidence_type=evidence_type,
            source=self.name,
            description=description,
            request_id=attack_request.request_id,
            response_id=attack_response.response_id,
            field_name=field_name,
            observed_value_preview=observed_value_preview,
            redacted=redacted,
        )

    def _attack_category(self, payload: PayloadCandidate) -> AttackCategory:
        if payload.attack_category is not None:
            return payload.attack_category
        category = payload.metadata.get("attack_category")
        if isinstance(category, str):
            try:
                return AttackCategory(category)
            except ValueError:
                return AttackCategory.INPUT_VALIDATION
        return AttackCategory.INPUT_VALIDATION

    def _metadata_value(self, metadata: Mapping[str, Any], key: str) -> str | None:
        value = metadata.get(key)
        return str(value) if value is not None else None

    def _is_success(self, response: ResponseRecord) -> bool:
        return 200 <= response.status_code < 300

    def _body_hash_changed(
        self,
        baseline_response: ResponseRecord,
        attack_response: ResponseRecord,
    ) -> bool:
        return (
            baseline_response.body_hash is not None
            and attack_response.body_hash is not None
            and baseline_response.body_hash != attack_response.body_hash
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
                    redacted=False,
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
        if baseline_response.status_code >= 400 and self._is_success(attack_response):
            evidence = [
                self._evidence(
                    attack_request,
                    attack_response,
                    "status_code",
                    "Attack response returned 2xx where baseline failed.",
                    f"{baseline_response.status_code}->{attack_response.status_code}",
                    redacted=False,
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
        for indicator, evidence_type in sorted(self._indicators.items()):
            if indicator in preview:
                evidence = [
                    self._evidence(
                        attack_request,
                        attack_response,
                        evidence_type,
                        "Generic server-side error indicator appeared in response preview.",
                        indicator,
                        redacted=True,
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
        "yslfuzz_cmd_probe",
        "yslfuzz_probe",
        "yslfuzz_sqli_probe",
        "yslfuzz_ssrf_probe",
        "yslfuzz_xss_probe",
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
                        redacted=False,
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
        if self._body_hash_changed(baseline_response, attack_response):
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
                redacted=True,
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
        return (
            abs(attack_size - baseline_size) / baseline_size
            >= self.config.response_size_delta_threshold_ratio
        )

    def _time_changed(self, baseline_time_ms: float, attack_time_ms: float) -> bool:
        if baseline_time_ms <= 0:
            return False
        return (
            attack_time_ms >= baseline_time_ms * 3
            and attack_time_ms - baseline_time_ms
            >= self.config.response_time_delta_threshold_ms
        )


class SensitiveDataExposureDetector(ResponseDetector):
    """Detect clearly sensitive-looking keys in response previews with redacted evidence."""

    detector_id = "detector_sensitive_data_exposure"
    name = "SensitiveDataExposureDetector"
    _keys = ("access_token", "api_key", "jwt", "password", "refresh_token", "secret", "token")

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
                    self._evidence(
                        attack_request,
                        attack_response,
                        "sensitive_key_exposure",
                        "Sensitive-looking key appeared in response preview.",
                        key,
                        redacted=True,
                        field_name=key,
                    )
                ]
                result = self._result(
                    attack_request,
                    attack_response,
                    attack_payload,
                    confidence=FindingConfidence.MEDIUM,
                    severity=FindingSeverity.MEDIUM,
                    evidence=evidence,
                    reason="sensitive data exposure indicator",
                )
                result.metadata["affected_location"] = ParameterLocation.BODY.value
                return [result]
        return []


class ValidationBypassDetector(ResponseDetector):
    """Detect possible invalid or boundary payload acceptance."""

    detector_id = "detector_validation_bypass"
    name = "ValidationBypassDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request
        if attack_payload.payload_kind not in {PayloadKind.INVALID, PayloadKind.BOUNDARY}:
            return []
        if not self._is_success(baseline_response) or not self._is_success(attack_response):
            return []

        confidence = FindingConfidence.MEDIUM if attack_response.status_code == 200 else FindingConfidence.LOW
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "validation_bypass",
                "Invalid or boundary payload received a successful response.",
                f"{baseline_response.status_code}->{attack_response.status_code}",
                redacted=False,
                field_name=self._metadata_value(attack_payload.metadata, "target_field"),
            )
        ]
        return [
            self._result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=confidence,
                severity=FindingSeverity.MEDIUM
                if confidence == FindingConfidence.MEDIUM
                else FindingSeverity.LOW,
                evidence=evidence,
                reason="Possible validation bypass: invalid or boundary payload was accepted.",
            )
        ]


class MassAssignmentDetector(ResponseDetector):
    """Detect possible controlled extra-field acceptance signals."""

    detector_id = "detector_mass_assignment"
    name = "MassAssignmentDetector"
    _marker_values = ("mass_assignment_marker", "yslfuzz_probe")

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request
        if not self._is_success(attack_response):
            return []
        extra_fields = self._extra_fields(attack_payload)
        if not extra_fields:
            return []

        preview = attack_response.body_preview or ""
        reflected = any(field in preview for field in extra_fields) or any(
            marker in preview for marker in self._marker_values
        )
        changed = self._body_hash_changed(baseline_response, attack_response)
        if not reflected and not changed:
            return []

        sorted_fields = sorted(extra_fields)
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "mass_assignment",
                "Controlled extra-field payload was accepted with a response signal.",
                ",".join(sorted_fields),
                redacted=True,
                field_name=sorted_fields[0],
            )
        ]
        confidence = FindingConfidence.MEDIUM if reflected else FindingConfidence.LOW
        return [
            self._result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=confidence,
                severity=FindingSeverity.MEDIUM
                if confidence == FindingConfidence.MEDIUM
                else FindingSeverity.LOW,
                evidence=evidence,
                reason="Possible mass assignment: controlled extra field appears accepted.",
            )
        ]

    def _extra_fields(self, payload: PayloadCandidate) -> set[str]:
        values: set[str] = set()
        for key in (
            "extra_field",
            "extra_fields",
            "added_field",
            "added_fields",
            "controlled_extra_field",
            "controlled_extra_fields",
        ):
            value = payload.metadata.get(key)
            if isinstance(value, str):
                values.add(value)
            elif isinstance(value, list):
                values.update(str(item) for item in value if item is not None)
        if payload.attack_category == AttackCategory.MASS_ASSIGNMENT:
            target_field = payload.metadata.get("target_field")
            if isinstance(target_field, str):
                values.add(target_field)
        if payload.metadata.get("safety_label") == "controlled_extra_fields":
            if isinstance(payload.body, dict):
                values.update(str(key) for key in payload.body if "yslfuzz" in str(key).lower())
            values.add("yslfuzz_probe")
        return {value for value in values if value}


class BasicAuthorizationBypassDetector(ResponseDetector):
    """Detect basic access-control anomalies from paired auth-related records."""

    detector_id = "detector_basic_authorization_bypass"
    name = "BasicAuthzBypassDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        if not self._auth_related(baseline_request, attack_request, attack_payload):
            return []
        if not self._is_success(baseline_response) or not self._is_success(attack_response):
            return []
        if baseline_response.status_code != attack_response.status_code:
            return []

        same_hash = (
            baseline_response.body_hash is not None
            and baseline_response.body_hash == attack_response.body_hash
        )
        similar_size = self._similar_size(
            baseline_response.body_size_bytes,
            attack_response.body_size_bytes,
        )
        if not same_hash and not similar_size:
            return []

        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "unauthorized_access",
                "Auth-related test returned a successful response similar to baseline.",
                f"{baseline_response.status_code}->{attack_response.status_code}",
                redacted=False,
            )
        ]
        confidence = FindingConfidence.MEDIUM if same_hash else FindingConfidence.LOW
        return [
            self._result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=confidence,
                severity=FindingSeverity.MEDIUM
                if confidence == FindingConfidence.MEDIUM
                else FindingSeverity.LOW,
                evidence=evidence,
                reason="Possible broken access control: auth-related request succeeded.",
            )
        ]

    def _auth_related(
        self,
        baseline_request: RequestRecord,
        attack_request: RequestRecord,
        attack_payload: PayloadCandidate,
    ) -> bool:
        metadata = {**baseline_request.metadata, **attack_request.metadata, **attack_payload.metadata}
        if attack_payload.attack_category in {
            AttackCategory.AUTH_BYPASS,
            AttackCategory.BROKEN_ACCESS_CONTROL,
        }:
            return True
        for key in (
            "altered_auth",
            "auth_test",
            "auth_variant",
            "authorization_test",
            "authz_test",
            "unauthenticated",
        ):
            if metadata.get(key):
                return True
        safety_label = metadata.get("safety_label")
        return isinstance(safety_label, str) and "auth" in safety_label.lower()

    def _similar_size(self, baseline_size: int, attack_size: int) -> bool:
        if baseline_size == attack_size:
            return True
        if baseline_size <= 0:
            return attack_size <= 32
        return abs(attack_size - baseline_size) / baseline_size <= 0.1
