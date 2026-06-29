from yslfuzz.models import (
    ApiStyle,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    RequestBodyDefinition,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.payloads import AttackTargetSelector, PayloadGenerator


def test_attack_targeting_finds_body_and_parameter_targets() -> None:
    endpoint = _endpoint()
    payload = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)

    targets = AttackTargetSelector().select(endpoint, payload)

    assert {target.name for target in targets} >= {"name", "website", "limit", "X-Trace-ID"}


def test_attack_targeting_skips_sensitive_fields_by_default() -> None:
    endpoint = _endpoint()
    payload = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)

    targets = AttackTargetSelector().select(endpoint, payload)

    assert "password" not in {target.name for target in targets}


def test_attack_targeting_allows_sensitive_fields_explicitly() -> None:
    endpoint = _endpoint()
    payload = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)

    targets = AttackTargetSelector().select(endpoint, payload, include_sensitive_fields=True)

    assert "password" in {target.name for target in targets}


def _endpoint() -> Endpoint:
    return Endpoint(
        api_schema_id="api_schema_1",
        name="createUser",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.POST,
        parameters=[
            Parameter(name="limit", location=ParameterLocation.QUERY, field_type=FieldType.INTEGER),
            Parameter(name="X-Trace-ID", location=ParameterLocation.HEADER, field_type=FieldType.STRING),
            Parameter(
                name="Authorization",
                location=ParameterLocation.HEADER,
                field_type=FieldType.STRING,
                sensitive=True,
            ),
        ],
        request_body=RequestBodyDefinition(
            content_type="application/json",
            fields=[
                FieldDefinition(name="name", field_type=FieldType.STRING),
                FieldDefinition(name="website", field_type=FieldType.URI),
                FieldDefinition(name="password", field_type=FieldType.STRING, sensitive=True),
            ],
        ),
    )
