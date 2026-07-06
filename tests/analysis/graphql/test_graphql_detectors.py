from yslfuzz.analysis.graphql import (
    GraphQLAuthorizationConsistencyDetector,
    GraphQLErrorDisclosureDetector,
    GraphQLInjectionMarkerDetector,
    GraphQLIntrospectionExposureDetector,
    GraphQLMassAssignmentDetector,
    GraphQLReflectionDetector,
    GraphQLSSRFMarkerDetector,
    GraphQLValidationBypassDetector,
)
from yslfuzz.models import (
    AttackCategory,
    ExecutionStatus,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ResponseRecord,
)


def test_graphql_error_disclosure_detector_detects_internal_error_and_redacts() -> None:
    results = GraphQLErrorDisclosureDetector().detect(
        _request("baseline"),
        _response("baseline", 200, '{"data":{"user":null}}'),
        _request("attack"),
        _response(
            "attack",
            200,
            '{"errors":[{"message":"Resolver exception: stack trace /app/server.py"}]}',
        ),
        _payload(PayloadKind.ATTACK, AttackCategory.INFORMATION_DISCLOSURE),
    )

    assert results
    assert results[0].metadata["attack_category"] == AttackCategory.INFORMATION_DISCLOSURE.value
    assert results[0].evidence[0].model_dump(mode="json")["observed_value_preview"] == "[REDACTED]"


def test_graphql_validation_bypass_detector_detects_invalid_payload_with_data() -> None:
    results = GraphQLValidationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200, '{"data":{"user":{"id":"1"}}}'),
        _request("attack"),
        _response("attack", 200, '{"data":{"user":{"id":"1"}}}'),
        _payload(PayloadKind.INVALID),
    )

    assert results
    assert results[0].severity == FindingSeverity.MEDIUM


def test_graphql_validation_bypass_detector_does_not_trigger_on_expected_errors() -> None:
    results = GraphQLValidationBypassDetector().detect(
        _request("baseline"),
        _response("baseline", 200, '{"data":{"user":{"id":"1"}}}'),
        _request("attack"),
        _response("attack", 200, '{"errors":[{"message":"validation failed"}]}'),
        _payload(PayloadKind.INVALID),
    )

    assert results == []


def test_graphql_introspection_exposure_detector_requires_probe_metadata() -> None:
    response = _response(
        "attack",
        200,
        '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}',
    )
    ordinary_payload = _payload(PayloadKind.ATTACK, AttackCategory.INFORMATION_DISCLOSURE)
    introspection_payload = _payload(
        PayloadKind.ATTACK,
        AttackCategory.GRAPHQL_INTROSPECTION_ABUSE,
        metadata={
            "graphql_mutation_operator": "attack_introspection_probe",
            "safety_label": "inert_introspection_probe",
        },
    )

    detector = GraphQLIntrospectionExposureDetector()

    assert detector.detect(_request("baseline"), _response("baseline"), _request("attack"), response, ordinary_payload) == []
    assert detector.detect(_request("baseline"), _response("baseline"), _request("attack"), response, introspection_payload)


def test_graphql_reflection_detector_detects_inert_marker_without_javascript() -> None:
    marker = "yslfuzz_graphql_reflection_marker"
    payload = _payload(
        PayloadKind.ATTACK,
        AttackCategory.XSS,
        metadata={"inert_marker": marker},
    )

    results = GraphQLReflectionDetector().detect(
        _request("baseline"),
        _response("baseline"),
        _request("attack"),
        _response("attack", 200, f'{{"data":{{"echo":"{marker}"}}}}'),
        payload,
    )

    assert results
    assert "<script" not in results[0].model_dump_json().lower()


def test_graphql_mass_assignment_detector_requires_metadata() -> None:
    response = _response("attack", 200, '{"data":{"createUser":{"ok":true}}}')
    detector = GraphQLMassAssignmentDetector()

    assert detector.detect(
        _request("baseline"),
        _response("baseline"),
        _request("attack"),
        response,
        _payload(PayloadKind.ATTACK, AttackCategory.XSS),
    ) == []
    assert detector.detect(
        _request("baseline"),
        _response("baseline"),
        _request("attack"),
        response,
        _payload(
            PayloadKind.ATTACK,
            AttackCategory.MASS_ASSIGNMENT,
            metadata={"graphql_mutation_operator": "attack_mass_assignment_extra_field"},
        ),
    )


def test_graphql_authorization_consistency_detector_detects_explicit_pair_only() -> None:
    detector = GraphQLAuthorizationConsistencyDetector()
    baseline_request = _request("baseline", metadata={"graphql_operation_name": "YSLFuzzUser"})
    attack_request = _request(
        "attack",
        metadata={
            "graphql_operation_name": "YSLFuzzUser",
            "graphql_authz_probe": True,
            "unauthenticated_variant": True,
        },
    )
    payload = _payload(
        PayloadKind.ATTACK,
        AttackCategory.BROKEN_ACCESS_CONTROL,
        metadata={"graphql_authz_probe": True, "graphql_operation_name": "YSLFuzzUser"},
    )

    assert detector.detect(
        baseline_request,
        _response("baseline", body_hash="same", body_size_bytes=30),
        attack_request,
        _response("attack", body_hash="same", body_size_bytes=30),
        payload,
    )
    assert detector.detect(
        baseline_request,
        _response("baseline", body_hash="same", body_size_bytes=30),
        _request("attack", metadata={"graphql_operation_name": "YSLFuzzUser"}),
        _response("attack", body_hash="same", body_size_bytes=30),
        _payload(PayloadKind.ATTACK, AttackCategory.BROKEN_ACCESS_CONTROL),
    ) == []


def test_graphql_injection_marker_detector_detects_safe_markers_only() -> None:
    for category, marker in (
        (AttackCategory.SQL_INJECTION, "yslfuzz_graphql_sql_marker"),
        (AttackCategory.NOSQL_INJECTION, "yslfuzz_graphql_nosql_marker"),
        (AttackCategory.COMMAND_INJECTION, "yslfuzz_graphql_command_marker"),
    ):
        payload = _payload(
            PayloadKind.ATTACK,
            category,
            metadata={"inert_marker": marker},
        )
        results = GraphQLInjectionMarkerDetector().detect(
            _request("baseline"),
            _response("baseline", body_hash="a"),
            _request("attack"),
            _response("attack", 200, f'{{"data":{{"echo":"{marker}"}}}}', body_hash="b"),
            payload,
        )

        assert results
        serialized = results[0].model_dump_json().lower()
        assert "' or" not in serialized
        assert "$ne" not in serialized
        assert "/bin" not in serialized


def test_graphql_ssrf_marker_detector_uses_safe_invalid_domain_marker() -> None:
    marker = "https://yslfuzz-ssrf-marker.invalid/resource"
    results = GraphQLSSRFMarkerDetector().detect(
        _request("baseline"),
        _response("baseline"),
        _request("attack"),
        _response("attack", 200, f'{{"errors":[{{"message":"invalid url {marker}"}}]}}'),
        _payload(PayloadKind.ATTACK, AttackCategory.SSRF, metadata={"inert_marker": marker}),
    )

    assert results
    serialized = results[0].model_dump_json().lower()
    assert "localhost" not in serialized
    assert "169.254.169.254" not in serialized


def _request(prefix: str, *, metadata: dict[str, object] | None = None) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_graphql_user",
        payload_id=f"payload_{prefix}",
        method=HttpMethod.POST,
        url="https://api.example.test/graphql",
        metadata={"api_style": "graphql", **(metadata or {})},
    )


def _response(
    prefix: str = "response",
    status_code: int = 200,
    body_preview: str = '{"data":{"ok":true}}',
    *,
    body_hash: str = "hash",
    body_size_bytes: int = 20,
) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=status_code,
        body_preview=body_preview,
        body_hash=body_hash,
        body_size_bytes=body_size_bytes,
        metadata={"execution_status": ExecutionStatus.COMPLETED.value},
    )


def _payload(
    kind: PayloadKind,
    category: AttackCategory | None = None,
    *,
    metadata: dict[str, object] | None = None,
) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_graphql_user",
        payload_kind=kind,
        attack_category=category if kind == PayloadKind.ATTACK else None,
        content_type="application/json",
        body={
            "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id } }",
            "variables": {"id": "yslfuzz-id-001"},
            "operationName": "YSLFuzzUser",
        },
        generation_strategy="graphql_test",
        seed=0,
        parent_payload_id="payload_valid",
        metadata={
            "api_style": "GRAPHQL",
            "graphql_operation_name": "YSLFuzzUser",
            "graphql_operation_type": "query",
            **(metadata or {}),
        },
    )
