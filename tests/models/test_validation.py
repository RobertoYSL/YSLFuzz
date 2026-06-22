import pytest
from pydantic import ValidationError

from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Endpoint,
    FieldType,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    Parameter,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    Report,
    ReportSummary,
    ScopeDefinition,
    SecurityFinding,
    Target,
    Protocol,
)


def test_rest_endpoint_requires_method_and_path() -> None:
    with pytest.raises(ValidationError, match="REST endpoint requires method and path"):
        Endpoint(api_schema_id="api_schema_1", name="broken", api_style=ApiStyle.REST)


def test_graphql_endpoint_requires_operation_metadata() -> None:
    with pytest.raises(ValidationError, match="GraphQL operation requires"):
        Endpoint(api_schema_id="api_schema_1", name="broken", api_style=ApiStyle.GRAPHQL)


def test_valid_endpoint_shapes_are_allowed() -> None:
    rest_endpoint = Endpoint(
        api_schema_id="api_schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )
    graphql_endpoint = Endpoint(
        api_schema_id="api_schema_1",
        name="user",
        api_style=ApiStyle.GRAPHQL,
        graphql_operation_type="query",
        graphql_operation_name="user",
    )

    assert rest_endpoint.method == HttpMethod.GET
    assert graphql_endpoint.graphql_operation_name == "user"


def test_attack_payload_requires_attack_category() -> None:
    with pytest.raises(ValidationError, match="ATTACK payload requires attack_category"):
        PayloadCandidate(
            endpoint_id="endpoint_1",
            payload_kind=PayloadKind.ATTACK,
            content_type="application/json",
            generation_strategy="unit-test",
            seed=1,
        )


def test_security_finding_requires_request_id() -> None:
    with pytest.raises(ValidationError, match="requires at least one request_id"):
        SecurityFinding(
            scan_run_id="scan_1",
            endpoint_id="endpoint_1",
            title="Missing request",
            description="Invalid finding",
            attack_category=AttackCategory.INFORMATION_DISCLOSURE,
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.LOW,
            request_ids=[],
        )


def test_high_severity_finding_requires_evidence() -> None:
    with pytest.raises(ValidationError, match="High severity findings require evidence"):
        SecurityFinding(
            scan_run_id="scan_1",
            endpoint_id="endpoint_1",
            title="High severity",
            description="Invalid finding",
            attack_category=AttackCategory.INFORMATION_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            request_ids=["request_1"],
        )


def test_report_requires_metrics() -> None:
    with pytest.raises(ValidationError):
        Report(scan_run_id="scan_1", summary=ReportSummary(), metrics=None)  # type: ignore[arg-type]


def test_target_requires_valid_base_url() -> None:
    with pytest.raises(ValidationError, match="base_url must be a valid"):
        Target(
            name="bad",
            base_url="not-a-url",
            api_style=ApiStyle.REST,
            protocol=Protocol.HTTP,
            scope=ScopeDefinition(allowed_hosts=["localhost"]),
        )


def test_parameter_creation() -> None:
    parameter = Parameter(
        name="id",
        location=ParameterLocation.PATH,
        field_type=FieldType.UUID,
        required=True,
    )

    assert parameter.required is True
