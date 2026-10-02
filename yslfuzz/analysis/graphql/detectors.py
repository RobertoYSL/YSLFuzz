"""Conservative GraphQL-specific response detectors."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from yslfuzz.analysis.config import AnalysisConfig
from yslfuzz.analysis.detectors import ResponseDetector
from yslfuzz.analysis.graphql.config import GraphQLAnalysisConfig
from yslfuzz.models.analysis import DetectorResult, Evidence
from yslfuzz.models.enums import AttackCategory, FindingConfidence, FindingSeverity, PayloadKind
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.payload import PayloadCandidate


YSLFUZZ_GRAPHQL_MARKERS = frozenset(
    {
        "yslfuzz_graphql_reflection_marker",
        "yslfuzz_graphql_sql_marker",
        "yslfuzz_graphql_nosql_marker",
        "yslfuzz_graphql_command_marker",
        "yslfuzz_graphql_ssrf_marker",
        "https://yslfuzz-ssrf-marker.invalid/resource",
        "yslfuzz_extra_field",
        "yslfuzz_extra_value",
        "yslfuzz_unknown_field",
    }
)


class GraphQLResponseDetector(ResponseDetector):
    """Base class for GraphQL-only detectors."""

    def __init__(self, config: object | None = None) -> None:
        super().__init__(config if isinstance(config, AnalysisConfig) else AnalysisConfig())
        self.graphql_config = GraphQLAnalysisConfig.from_object(config)

    def _is_graphql_record(
        self,
        request: RequestRecord,
        payload: PayloadCandidate,
    ) -> bool:
        payload_api_style = payload.metadata.get("api_style")
        if isinstance(payload_api_style, str) and payload_api_style.lower() == "rest":
            return False
        if isinstance(payload.body, dict) and isinstance(payload.body.get("query"), str):
            return True
        payload_values = (
            payload.metadata.get("api_style"),
            payload.metadata.get("graphql_operation_name"),
            payload.metadata.get("graphql_operation_type"),
        )
        if isinstance(payload.body, dict) and "query" not in payload.body and not any(payload_values):
            return False
        if any(
            isinstance(value, str)
            and (value.lower() == "graphql" or value.startswith("YSLFuzz"))
            for value in payload_values
        ):
            return True
        values = (
            request.metadata.get("api_style"),
        )
        if any(isinstance(value, str) and value.lower() == "graphql" for value in values):
            return True
        return False

    def _json_body(self, response: ResponseRecord) -> Mapping[str, Any]:
        if not response.body_preview:
            return {}
        try:
            value = json.loads(response.body_preview)
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    def _has_graphql_errors(self, response: ResponseRecord, body: Mapping[str, Any]) -> bool:
        if response.metadata.get("graphql_has_errors") is True:
            return True
        errors = body.get("errors")
        return isinstance(errors, list) and len(errors) > 0

    def _graphql_error_texts(self, body: Mapping[str, Any]) -> list[str]:
        errors = body.get("errors")
        if not isinstance(errors, list):
            return []
        texts: list[str] = []
        for error in errors[: self.graphql_config.max_error_messages_to_analyze]:
            if isinstance(error, dict):
                for key in ("message", "path", "extensions"):
                    value = error.get(key)
                    if value is not None:
                        texts.append(self._bounded_preview(value))
            elif error is not None:
                texts.append(self._bounded_preview(error))
        return texts

    def _contains_internal_detail(self, text: str) -> bool:
        lowered = text.lower()
        indicators = (
            "stack trace",
            "traceback",
            "exception",
            "resolver",
            "database",
            "sql",
            "postgres",
            "mysql",
            "mongodb",
            "sequelize",
            "prisma",
            "django",
            "graphql-java",
            "apollo",
            "path",
            "extensions",
        )
        return any(indicator in lowered for indicator in indicators)

    def _response_text(self, response: ResponseRecord) -> str:
        return response.body_preview or ""

    def _bounded_preview(self, value: object) -> str:
        preview = json.dumps(value, sort_keys=True, default=str) if not isinstance(value, str) else value
        return preview[: self.graphql_config.max_evidence_preview_chars]

    def _graphql_result(
        self,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
        *,
        confidence: FindingConfidence,
        severity: FindingSeverity,
        evidence: list[Evidence],
        reason: str,
        category: AttackCategory | None = None,
        title: str | None = None,
    ) -> DetectorResult:
        result = self._result(
            attack_request,
            attack_response,
            attack_payload,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            reason=reason,
        )
        if category is not None:
            result.metadata["attack_category"] = category.value
        if title is not None:
            result.metadata["graphql_title"] = title
        result.metadata["api_style"] = "graphql"
        result.metadata["graphql_operation_name"] = attack_payload.metadata.get(
            "graphql_operation_name"
        )
        result.metadata["graphql_operation_type"] = attack_payload.metadata.get(
            "graphql_operation_type"
        )
        result.metadata["graphql_detector"] = True
        return result


class GraphQLErrorDisclosureDetector(GraphQLResponseDetector):
    """Detect possible internal detail leakage in GraphQL errors."""

    detector_id = "detector_graphql_error_disclosure"
    name = "GraphQLErrorDisclosureDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_error_disclosure:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        body = self._json_body(attack_response)
        if not self._has_graphql_errors(attack_response, body):
            return []
        texts = self._graphql_error_texts(body)
        matched = [text for text in texts if self._contains_internal_detail(text)]
        if not matched:
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_ERROR_DISCLOSURE",
                "GraphQL error response contained internal-looking implementation detail.",
                matched[0],
                redacted=True,
            )
        ]
        confidence = FindingConfidence.MEDIUM if len(matched) > 1 else FindingConfidence.LOW
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=confidence,
                severity=FindingSeverity.MEDIUM
                if confidence == FindingConfidence.MEDIUM
                else FindingSeverity.LOW,
                evidence=evidence,
                reason="GraphQL errors contain internal-looking details.",
                category=AttackCategory.INFORMATION_DISCLOSURE,
                title="Possible GraphQL Error Disclosure",
            )
        ]


class GraphQLValidationBypassDetector(GraphQLResponseDetector):
    """Detect invalid or boundary GraphQL payloads accepted with data and no errors."""

    detector_id = "detector_graphql_validation_bypass"
    name = "GraphQLValidationBypassDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_validation_bypass:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if attack_payload.payload_kind not in {PayloadKind.INVALID, PayloadKind.BOUNDARY}:
            return []
        if not self._is_success(attack_response):
            return []
        body = self._json_body(attack_response)
        if self._has_graphql_errors(attack_response, body) or "data" not in body:
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_VALIDATION_BYPASS",
                "Invalid or boundary GraphQL payload received data without GraphQL errors.",
                f"status={attack_response.status_code}",
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM,
                severity=FindingSeverity.MEDIUM,
                evidence=evidence,
                reason="Invalid or boundary GraphQL payload appears accepted.",
                category=AttackCategory.INPUT_VALIDATION,
                title="Possible GraphQL Validation Bypass",
            )
        ]


class GraphQLIntrospectionExposureDetector(GraphQLResponseDetector):
    """Detect introspection data only from already executed introspection probes."""

    detector_id = "detector_graphql_introspection_exposure"
    name = "GraphQLIntrospectionExposureDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_introspection_exposure:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if not self._is_introspection_probe(attack_payload):
            return []
        body = self._json_body(attack_response)
        if self._has_graphql_errors(attack_response, body):
            return []
        text = json.dumps(body, sort_keys=True, default=str)
        strong = "__schema" in text and ("queryType" in text or "types" in text)
        if not strong:
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_INTROSPECTION_EXPOSURE",
                "Executed introspection probe returned GraphQL schema metadata.",
                "__schema",
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM,
                severity=FindingSeverity.MEDIUM,
                evidence=evidence,
                reason="GraphQL introspection probe returned schema metadata.",
                category=AttackCategory.INFORMATION_DISCLOSURE,
                title="Possible GraphQL Introspection Exposure",
            )
        ]

    def _is_introspection_probe(self, payload: PayloadCandidate) -> bool:
        return (
            payload.metadata.get("graphql_mutation_operator") == "attack_introspection_probe"
            or payload.metadata.get("safety_label") == "inert_introspection_probe"
            or payload.attack_category == AttackCategory.GRAPHQL_INTROSPECTION_ABUSE
        )


class GraphQLReflectionDetector(GraphQLResponseDetector):
    """Detect exact reflection of inert YSLFuzz GraphQL markers."""

    detector_id = "detector_graphql_reflection"
    name = "GraphQLReflectionDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_reflection_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        marker = attack_payload.metadata.get("inert_marker")
        if not isinstance(marker, str) or marker not in YSLFUZZ_GRAPHQL_MARKERS:
            return []
        if marker not in self._response_text(attack_response):
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_MARKER_REFLECTION",
                "Inert YSLFuzz GraphQL marker appeared in the response preview.",
                marker,
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM,
                severity=FindingSeverity.LOW,
                evidence=evidence,
                reason="Inert GraphQL marker was reflected.",
                category=AttackCategory.XSS,
                title="Possible GraphQL Marker Reflection",
            )
        ]


class GraphQLMassAssignmentDetector(GraphQLResponseDetector):
    """Detect possible acceptance of a safe extra input field marker."""

    detector_id = "detector_graphql_mass_assignment"
    name = "GraphQLMassAssignmentDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_mass_assignment_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if not self._is_mass_assignment_probe(attack_payload):
            return []
        if not self._is_success(attack_response):
            return []
        body = self._json_body(attack_response)
        if self._has_graphql_errors(attack_response, body):
            return []
        marker = str(attack_payload.metadata.get("inert_marker") or "yslfuzz_extra_field")
        reflected = marker in self._response_text(attack_response)
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_MASS_ASSIGNMENT",
                "Safe extra GraphQL input field marker appears accepted.",
                marker,
                redacted=True,
                field_name=marker,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM if reflected else FindingConfidence.LOW,
                severity=FindingSeverity.MEDIUM if reflected else FindingSeverity.LOW,
                evidence=evidence,
                reason="Safe extra GraphQL input field produced a successful response.",
                category=AttackCategory.MASS_ASSIGNMENT,
                title="Possible GraphQL Mass Assignment",
            )
        ]

    def _is_mass_assignment_probe(self, payload: PayloadCandidate) -> bool:
        return (
            payload.attack_category == AttackCategory.MASS_ASSIGNMENT
            or payload.metadata.get("graphql_mutation_operator")
            in {"attack_mass_assignment_extra_field", "input_object_extra_field"}
            or payload.metadata.get("safety_label") == "inert_mass_assignment_probe"
        )


class GraphQLAuthorizationConsistencyDetector(GraphQLResponseDetector):
    """Detect suspicious paired auth/no-auth or cross-profile GraphQL success."""

    detector_id = "detector_graphql_authorization_consistency"
    name = "GraphQLAuthzConsistencyDetector"

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        if not self.graphql_config.enable_graphql_authorization_consistency:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if not self._is_authz_probe(baseline_request, attack_request, attack_payload):
            return []
        if not self._same_operation(baseline_request, attack_request, attack_payload):
            return []
        if not self._is_success(baseline_response) or not self._is_success(attack_response):
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
                "GRAPHQL_AUTHORIZATION_CONSISTENCY",
                "Explicit GraphQL authz probe succeeded similarly to authenticated baseline.",
                f"{baseline_response.status_code}->{attack_response.status_code}",
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM if same_hash else FindingConfidence.LOW,
                severity=FindingSeverity.MEDIUM if same_hash else FindingSeverity.LOW,
                evidence=evidence,
                reason="Explicit GraphQL authorization consistency probe succeeded.",
                category=AttackCategory.BROKEN_ACCESS_CONTROL,
                title="Possible GraphQL Broken Access Control",
            )
        ]

    def _is_authz_probe(
        self,
        baseline_request: RequestRecord,
        attack_request: RequestRecord,
        payload: PayloadCandidate,
    ) -> bool:
        metadata = {**baseline_request.metadata, **attack_request.metadata, **payload.metadata}
        return any(
            bool(metadata.get(key))
            for key in (
                "graphql_authz_probe",
                "authorization_consistency_check",
                "authz_test",
                "unauthenticated_variant",
                "alternate_auth_profile_variant",
            )
        )

    def _same_operation(
        self,
        baseline_request: RequestRecord,
        attack_request: RequestRecord,
        payload: PayloadCandidate,
    ) -> bool:
        baseline_name = baseline_request.metadata.get("graphql_operation_name")
        attack_name = attack_request.metadata.get("graphql_operation_name")
        payload_name = payload.metadata.get("graphql_operation_name")
        if baseline_name is None:
            return baseline_request.endpoint_id == attack_request.endpoint_id
        return baseline_name in {attack_name, payload_name}

    def _similar_size(self, baseline_size: int, attack_size: int) -> bool:
        if baseline_size == attack_size:
            return True
        if baseline_size <= 0:
            return attack_size <= 32
        return abs(attack_size - baseline_size) / baseline_size <= 0.1


class GraphQLInjectionMarkerDetector(GraphQLResponseDetector):
    """Detect inert SQL/NoSQL/command marker signals without exploit strings."""

    detector_id = "detector_graphql_injection_marker"
    name = "GraphQLInjectionMarkerDetector"

    _categories = {
        AttackCategory.SQL_INJECTION: (
            "yslfuzz_graphql_sql_marker",
            "Possible GraphQL SQL Injection Signal",
        ),
        AttackCategory.NOSQL_INJECTION: (
            "yslfuzz_graphql_nosql_marker",
            "Possible GraphQL NoSQL Injection Signal",
        ),
        AttackCategory.COMMAND_INJECTION: (
            "yslfuzz_graphql_command_marker",
            "Possible GraphQL Command Injection Signal",
        ),
    }

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        if not self.graphql_config.enable_graphql_injection_marker_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if attack_payload.attack_category not in self._categories:
            return []
        marker, title = self._categories[attack_payload.attack_category]
        body = self._json_body(attack_response)
        response_text = self._response_text(attack_response)
        reflected = marker in response_text
        error_signal = self._has_graphql_errors(attack_response, body) and any(
            self._contains_internal_detail(text) for text in self._graphql_error_texts(body)
        )
        changed = self._body_hash_changed(baseline_response, attack_response)
        if not reflected and not error_signal and not changed:
            return []
        evidence_type = f"GRAPHQL_{attack_payload.attack_category.value}_MARKER"
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                evidence_type,
                "Inert GraphQL injection marker produced a conservative response signal.",
                marker,
                redacted=False,
            )
        ]
        confidence = FindingConfidence.MEDIUM if reflected or error_signal else FindingConfidence.LOW
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=confidence,
                severity=FindingSeverity.MEDIUM
                if confidence == FindingConfidence.MEDIUM
                else FindingSeverity.LOW,
                evidence=evidence,
                reason="Inert GraphQL injection marker produced a response signal.",
                category=attack_payload.attack_category,
                title=title,
            )
        ]


class GraphQLSSRFMarkerDetector(GraphQLResponseDetector):
    """Detect safe SSRF marker handling without real callbacks or internal targets."""

    detector_id = "detector_graphql_ssrf_marker"
    name = "GraphQLSSRFMarkerDetector"
    _markers = ("yslfuzz_graphql_ssrf_marker", "https://yslfuzz-ssrf-marker.invalid/resource")
    _blocked_terms = ("localhost", "127.0.0.1", "169.254.169.254", "metadata.google")

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_ssrf_marker_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if attack_payload.attack_category != AttackCategory.SSRF:
            return []
        marker = str(attack_payload.metadata.get("inert_marker") or "")
        if marker not in self._markers or any(term in marker.lower() for term in self._blocked_terms):
            return []
        response_text = self._response_text(attack_response)
        lowered = response_text.lower()
        reflected = marker in response_text
        validation_signal = any(word in lowered for word in ("url", "fetch", "invalid", "blocked"))
        if not reflected and not validation_signal:
            return []
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_SSRF_MARKER",
                "Safe GraphQL SSRF marker produced URL-handling response signal.",
                marker,
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.MEDIUM if reflected else FindingConfidence.LOW,
                severity=FindingSeverity.MEDIUM if reflected else FindingSeverity.LOW,
                evidence=evidence,
                reason="Safe GraphQL SSRF marker produced a response signal.",
                category=AttackCategory.SSRF,
                title="Possible GraphQL SSRF Handling Signal",
            )
        ]


class GraphQLFieldSuggestionDetector(GraphQLResponseDetector):
    """Detect information disclosure in GraphQL field suggestions ('Did you mean...')."""

    detector_id = "detector_graphql_field_suggestion"
    name = "GraphQLFieldSuggestionDetector"

    def detect_baseline(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
    ) -> list[DetectorResult]:
        if not self.graphql_config.enable_graphql_field_suggestion_detection:
            return []
        payload = PayloadCandidate(
            endpoint_id=baseline_request.endpoint_id,
            payload_kind=PayloadKind.VALID,
            content_type="application/json",
            body={},
            generation_strategy="baseline",
            seed=0,
            metadata={"api_style": "graphql"},
        )
        return self._detect_suggestions(baseline_request, baseline_response, payload)

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request, baseline_response
        if not self.graphql_config.enable_graphql_field_suggestion_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        return self._detect_suggestions(attack_request, attack_response, attack_payload)

    def _detect_suggestions(
        self,
        request: RequestRecord,
        response: ResponseRecord,
        payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        body = self._json_body(response)
        error_texts = self._graphql_error_texts(body)
        if not error_texts and response.body_preview:
            error_texts = [response.body_preview]

        matched_suggestions: list[str] = []
        for text in error_texts:
            match = re.search(r'did you mean\s+([^\n?]+)\??', text, re.IGNORECASE)
            if match:
                matched_suggestions.append(match.group(0).strip())
            elif "did you mean" in text.lower():
                matched_suggestions.append("Did you mean ...")

        if not matched_suggestions:
            return []

        preview = "; ".join(matched_suggestions)[: self.graphql_config.max_evidence_preview_chars]
        evidence = [
            self._evidence(
                request,
                response,
                "GRAPHQL_FIELD_SUGGESTION",
                "GraphQL engine leaked schema field names via field suggestions ('Did you mean...').",
                preview,
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                request,
                response,
                payload,
                confidence=FindingConfidence.HIGH,
                severity=FindingSeverity.LOW,
                evidence=evidence,
                reason="GraphQL field suggestions leak valid schema field names.",
                category=AttackCategory.INFORMATION_DISCLOSURE,
                title="GraphQL Field Suggestions Information Disclosure",
            )
        ]


class GraphQLBooleanSqlInjectionDetector(GraphQLResponseDetector):
    """Detect boolean-based SQL injection via differential record counts in GraphQL queries."""

    detector_id = "detector_graphql_boolean_sqli"
    name = "GraphQLBooleanSqlInjectionDetector"

    _boolean_indicators = (
        "' or '",
        "' OR '",
        " or 1=1",
        " OR 1=1",
        "yslfuzz_sqli",
        "yslfuzz_probe",
    )

    def detect(
        self,
        baseline_request: RequestRecord,
        baseline_response: ResponseRecord,
        attack_request: RequestRecord,
        attack_response: ResponseRecord,
        attack_payload: PayloadCandidate,
    ) -> list[DetectorResult]:
        del baseline_request
        if not self.graphql_config.enable_graphql_boolean_sqli_detection:
            return []
        if not self._is_graphql_record(attack_request, attack_payload):
            return []
        if attack_payload.attack_category != AttackCategory.SQL_INJECTION:
            return []
        if not (self._is_success(baseline_response) and self._is_success(attack_response)):
            return []

        payload_str = str(attack_payload.body).lower()
        if not any(ind.lower() in payload_str for ind in self._boolean_indicators):
            return []

        baseline_data = self._json_body(baseline_response).get("data")
        attack_data = self._json_body(attack_response).get("data")

        expansions: list[tuple[str, int, int]] = []
        if isinstance(baseline_data, dict) and isinstance(attack_data, dict):
            baseline_counts = dict(self._extract_list_counts(baseline_data))
            attack_counts = dict(self._extract_list_counts(attack_data))
            for path, attack_count in attack_counts.items():
                baseline_count = baseline_counts.get(path, 0)
                if attack_count > baseline_count and (attack_count >= baseline_count + 2 or baseline_count == 0):
                    expansions.append((path, baseline_count, attack_count))
        elif isinstance(baseline_data, dict) and attack_response.body_preview and "data" in attack_response.body_preview:
            baseline_counts = dict(self._extract_list_counts(baseline_data))
            for path, baseline_count in baseline_counts.items():
                field = path.split(".")[-1]
                if field in attack_response.body_preview:
                    att_approx = attack_response.body_preview.count('"id":') or attack_response.body_preview.count("'id':")
                    if att_approx > baseline_count and (att_approx >= baseline_count + 2 or baseline_count == 0):
                        expansions.append((path, baseline_count, att_approx))

        if not expansions:
            return []

        primary_path, base_cnt, att_cnt = expansions[0]
        preview = f"path='{primary_path}', baseline_count={base_cnt}, attack_count={att_cnt}"
        evidence = [
            self._evidence(
                attack_request,
                attack_response,
                "GRAPHQL_BOOLEAN_SQL_INJECTION",
                (
                    f"Injected boolean SQL condition expanded result list from "
                    f"{base_cnt} to {att_cnt} items under '{primary_path}'."
                ),
                preview,
                redacted=False,
            )
        ]
        return [
            self._graphql_result(
                attack_request,
                attack_response,
                attack_payload,
                confidence=FindingConfidence.HIGH,
                severity=FindingSeverity.HIGH,
                evidence=evidence,
                reason="Boolean SQL injection condition expanded query results despite 200 OK status.",
                category=AttackCategory.SQL_INJECTION,
                title="Possible Boolean-based SQL Injection in GraphQL Query",
            )
        ]

    def _extract_list_counts(self, mapping: Mapping[str, Any], path: str = "data") -> list[tuple[str, int]]:
        counts: list[tuple[str, int]] = []
        for key, value in mapping.items():
            curr = f"{path}.{key}"
            if isinstance(value, list):
                counts.append((curr, len(value)))
            elif isinstance(value, dict):
                counts.extend(self._extract_list_counts(value, curr))
        return counts


def default_graphql_detectors(config: object | None = None) -> list[ResponseDetector]:
    """Return GraphQL detectors in deterministic order."""
    return [
        GraphQLErrorDisclosureDetector(config),
        GraphQLValidationBypassDetector(config),
        GraphQLIntrospectionExposureDetector(config),
        GraphQLReflectionDetector(config),
        GraphQLMassAssignmentDetector(config),
        GraphQLAuthorizationConsistencyDetector(config),
        GraphQLInjectionMarkerDetector(config),
        GraphQLSSRFMarkerDetector(config),
        GraphQLFieldSuggestionDetector(config),
        GraphQLBooleanSqlInjectionDetector(config),
    ]
