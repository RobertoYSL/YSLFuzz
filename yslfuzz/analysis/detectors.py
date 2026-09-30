"""Conservative response detectors for opt-in attack analysis."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.models.analysis import DetectorResult, Evidence
from yslfuzz.models.enums import (
    AttackCategory,
    FieldType,
    FindingConfidence,
    FindingSeverity,
    ParameterLocation,
    PayloadKind,
)
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Endpoint, ResponseDefinition


class ResponseDetector(ABC):
    """Base interface for response analysis detectors."""

    detector_id: str
    name: str
    version = "0.1.0"

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        self.config = config or AnalysisConfig()

    def detect_baseline(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
    ) -> list[DetectorResult]:
        """Return detector results for a baseline response alone."""
        return []

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


class BaselineCrashDetector(ResponseDetector):
    """Detect unhandled 5xx server crashes on conforming baseline requests."""

    detector_id = "detector_baseline_crash"
    name = "BaselineCrashDetector"

    def detect_baseline(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
    ) -> list[DetectorResult]:
        if baseline_response.status_code >= 500:
            evidence = [
                self._evidence(
                    baseline_request,
                    baseline_response,
                    "baseline_5xx_crash",
                    f"Baseline request conforming to schema caused unhandled {baseline_response.status_code} server error.",
                    f"HTTP {baseline_response.status_code}",
                    redacted=False,
                )
            ]
            result = DetectorResult(
                detector_id=self.detector_id,
                request_id=baseline_request.request_id,
                response_id=baseline_response.response_id,
                matched=True,
                confidence=FindingConfidence.HIGH,
                severity=FindingSeverity.HIGH,
                evidence=evidence,
                reason=f"Baseline request caused unhandled {baseline_response.status_code} Internal Server Error",
            )
            result.metadata.update(
                {
                    "detector_name": self.name,
                    "detector_version": self.version,
                    "endpoint_id": baseline_request.endpoint_id,
                    "endpoint_identity": f"{baseline_request.method.value} {urlparse(baseline_request.url).path or '/'}",
                    "attack_category": AttackCategory.INPUT_VALIDATION.value,
                    "status_code": baseline_response.status_code,
                    "status_code_class": f"{str(baseline_response.status_code)[0]}xx",
                    "oracle_type": "baseline_crash",
                }
            )
            return [result]
        return []

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del attack_request, attack_response, attack_payload
        if baseline_response.status_code >= 500:
            return self.detect_baseline(baseline_request, baseline_response)
        return []


class SchemaConformanceDetector(ResponseDetector):
    """Detect violations between server responses and documented OpenAPI response definitions."""

    detector_id = "detector_schema_conformance"
    name = "SchemaConformanceDetector"

    def __init__(
        self,
        config: AnalysisConfig | None = None,
        endpoints_by_id: Mapping[str, Endpoint] | None = None,
    ) -> None:
        super().__init__(config=config)
        self._endpoints_by_id: dict[str, Endpoint] = (
            dict(endpoints_by_id) if endpoints_by_id is not None else {}
        )

    def set_endpoints(self, endpoints: Sequence[Endpoint]) -> None:
        """Register endpoints with their documented response schemas."""
        self._endpoints_by_id = {endpoint.endpoint_id: endpoint for endpoint in endpoints}

    def check_response(
        self,
        request: RequestRecord,
        response: ResponseRecord,
    ) -> list[DetectorResult]:
        endpoint = self._endpoints_by_id.get(request.endpoint_id)
        if endpoint is None or not endpoint.responses:
            return []

        results: list[DetectorResult] = []
        matching_def = self._find_matching_response_def(endpoint, response.status_code)

        if matching_def is None:
            is_5xx = response.status_code >= 500
            severity = FindingSeverity.HIGH if is_5xx else FindingSeverity.MEDIUM
            reason = (
                f"Undocumented 5xx status code {response.status_code} not specified in schema responses"
                if is_5xx
                else f"Undocumented status code {response.status_code} not specified in schema responses"
            )
            evidence = [
                self._evidence(
                    request,
                    response,
                    "undocumented_status_code",
                    reason,
                    str(response.status_code),
                    redacted=False,
                )
            ]
            result = DetectorResult(
                detector_id=self.detector_id,
                request_id=request.request_id,
                response_id=response.response_id,
                matched=True,
                confidence=FindingConfidence.HIGH,
                severity=severity,
                evidence=evidence,
                reason=reason,
            )
            result.metadata.update(
                {
                    "detector_name": self.name,
                    "detector_version": self.version,
                    "endpoint_id": request.endpoint_id,
                    "endpoint_identity": f"{request.method.value} {urlparse(request.url).path or '/'}",
                    "attack_category": AttackCategory.INPUT_VALIDATION.value,
                    "status_code": response.status_code,
                    "status_code_class": f"{str(response.status_code)[0]}xx",
                    "conformance_violation": "undocumented_status_code",
                }
            )
            results.append(result)
            return results

        if matching_def.content_type and response.headers:
            content_type_header = None
            for key, val in response.headers.items():
                if key.lower() == "content-type":
                    content_type_header = str(val).lower()
                    break
            if content_type_header and matching_def.content_type.lower() not in content_type_header:
                reason = (
                    f"Response Content-Type '{content_type_header}' does not match "
                    f"documented '{matching_def.content_type}'"
                )
                evidence = [
                    self._evidence(
                        request,
                        response,
                        "content_type_mismatch",
                        reason,
                        content_type_header,
                        redacted=False,
                    )
                ]
                result = DetectorResult(
                    detector_id=self.detector_id,
                    request_id=request.request_id,
                    response_id=response.response_id,
                    matched=True,
                    confidence=FindingConfidence.HIGH,
                    severity=FindingSeverity.MEDIUM,
                    evidence=evidence,
                    reason=reason,
                )
                result.metadata.update(
                    {
                        "detector_name": self.name,
                        "detector_version": self.version,
                        "endpoint_id": request.endpoint_id,
                        "endpoint_identity": f"{request.method.value} {urlparse(request.url).path or '/'}",
                        "attack_category": AttackCategory.INPUT_VALIDATION.value,
                        "status_code": response.status_code,
                        "conformance_violation": "content_type_mismatch",
                    }
                )
                results.append(result)

        if matching_def.fields and response.body_preview:
            parsed = self._parse_json_preview(response.body_preview)
            if isinstance(parsed, dict):
                for field in matching_def.fields:
                    if field.required and field.name not in parsed:
                        reason = f"Required field '{field.name}' missing from response body"
                        evidence = [
                            self._evidence(
                                request,
                                response,
                                "missing_required_field",
                                reason,
                                field.name,
                                redacted=False,
                                field_name=field.name,
                            )
                        ]
                        result = DetectorResult(
                            detector_id=self.detector_id,
                            request_id=request.request_id,
                            response_id=response.response_id,
                            matched=True,
                            confidence=FindingConfidence.HIGH,
                            severity=FindingSeverity.MEDIUM,
                            evidence=evidence,
                            reason=reason,
                        )
                        result.metadata.update(
                            {
                                "detector_name": self.name,
                                "detector_version": self.version,
                                "endpoint_id": request.endpoint_id,
                                "endpoint_identity": f"{request.method.value} {urlparse(request.url).path or '/'}",
                                "attack_category": AttackCategory.INPUT_VALIDATION.value,
                                "status_code": response.status_code,
                                "target_field": field.name,
                                "conformance_violation": "missing_required_field",
                            }
                        )
                        results.append(result)
                    elif field.name in parsed and parsed[field.name] is not None:
                        val = parsed[field.name]
                        type_error = self._check_field_type(field.field_type, val)
                        if type_error:
                            reason = f"Field '{field.name}' type mismatch: expected {field.field_type.value}, got {type_error}"
                            evidence = [
                                self._evidence(
                                    request,
                                    response,
                                    "field_type_mismatch",
                                    reason,
                                    type_error,
                                    redacted=False,
                                    field_name=field.name,
                                )
                            ]
                            result = DetectorResult(
                                detector_id=self.detector_id,
                                request_id=request.request_id,
                                response_id=response.response_id,
                                matched=True,
                                confidence=FindingConfidence.MEDIUM,
                                severity=FindingSeverity.LOW,
                                evidence=evidence,
                                reason=reason,
                            )
                            result.metadata.update(
                                {
                                    "detector_name": self.name,
                                    "detector_version": self.version,
                                    "endpoint_id": request.endpoint_id,
                                    "endpoint_identity": f"{request.method.value} {urlparse(request.url).path or '/'}",
                                    "attack_category": AttackCategory.INPUT_VALIDATION.value,
                                    "status_code": response.status_code,
                                    "target_field": field.name,
                                    "conformance_violation": "field_type_mismatch",
                                }
                            )
                            results.append(result)

        return results

    def _check_field_type(self, expected_type: FieldType, val: Any) -> str | None:
        if expected_type == FieldType.INTEGER:
            if not isinstance(val, int) or isinstance(val, bool):
                return type(val).__name__
        elif expected_type == FieldType.BOOLEAN:
            if not isinstance(val, bool):
                return type(val).__name__
        elif expected_type == FieldType.STRING:
            if not isinstance(val, str):
                return type(val).__name__
        elif expected_type == FieldType.ARRAY:
            if not isinstance(val, list):
                return type(val).__name__
        elif expected_type == FieldType.OBJECT:
            if not isinstance(val, dict):
                return type(val).__name__
        return None

    def _parse_json_preview(self, body_preview: str | None) -> Any:
        if not body_preview:
            return None
        text = body_preview.strip()
        if (text.startswith("{") and text.endswith("}")) or (
            text.startswith("[") and text.endswith("]")
        ):
            try:
                return json.loads(text)
            except Exception:
                return None
        return None

    def _find_matching_response_def(
        self,
        endpoint: Endpoint,
        status_code: int,
    ) -> ResponseDefinition | None:
        range_match = None
        default_match = None
        status_str = str(status_code)
        range_str = f"{status_code // 100}xx"

        for resp in endpoint.responses:
            code_str = str(resp.status_code).lower()
            if code_str == status_str:
                return resp
            if code_str == range_str:
                range_match = resp
            elif code_str in ("default", "default_response"):
                default_match = resp

        return range_match or default_match

    def detect_baseline(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
    ) -> list[DetectorResult]:
        return self.check_response(baseline_request, baseline_response)

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response, attack_payload
        return self.check_response(attack_request, attack_response)


class BolaDetector(ResponseDetector):
    """Detect Broken Object Level Authorization (BOLA/IDOR) where secondary identity accesses primary identity's resource."""

    detector_id = "detector_bola"
    name = "BolaDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self._is_bola_test(attack_request, attack_payload):
            return []

        if self._is_success(attack_response):
            target_res = (
                attack_request.metadata.get("target_resource_id")
                or attack_payload.metadata.get("target_resource_id")
                or "object"
            )
            reason = (
                f"Broken Object Level Authorization (BOLA/IDOR) detected: "
                f"secondary identity accessed resource '{target_res}' with status {attack_response.status_code}"
            )
            evidence = [
                self._evidence(
                    attack_request,
                    attack_response,
                    "bola_unauthorized_access",
                    reason,
                    f"HTTP {attack_response.status_code} for secondary user accessing primary user resource",
                    redacted=False,
                )
            ]
            result = self._result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.HIGH,
                severity=FindingSeverity.HIGH,
                evidence=evidence,
                reason=reason,
            )
            result.metadata["attack_category"] = AttackCategory.BROKEN_ACCESS_CONTROL.value
            result.metadata["oracle_type"] = "bola_differential"
            return [result]

        return []

    def _is_bola_test(self, request: RequestRecord, payload: PayloadCandidate) -> bool:
        if request.metadata.get("bola_test") or payload.metadata.get("bola_test"):
            return True
        if payload.attack_category == AttackCategory.BROKEN_ACCESS_CONTROL:
            return bool(request.metadata.get("multi_user_differential"))
        return False
