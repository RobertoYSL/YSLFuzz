from datetime import date, datetime
from pathlib import Path
from uuid import UUID

from yslfuzz.discovery import OpenAPIParser
from yslfuzz.models import (
    ApiStyle,
    Constraint,
    ConstraintType,
    Endpoint,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    PayloadKind,
    REDACTED_VALUE,
    RequestBodyDefinition,
    TypeReference,
)
from yslfuzz.payloads import PayloadGenerator


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


def test_generates_json_body_payload_for_post_endpoint() -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "createUser")

    payload = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)

    assert payload.endpoint_id == endpoint.endpoint_id
    assert payload.payload_kind == PayloadKind.VALID
    assert payload.content_type == "application/json"
    assert isinstance(payload.body, dict)
    assert {"email", "name"}.issubset(payload.body)
    assert payload.body["email"].endswith("@example.test")
    assert payload.body["role"] in {"user", "admin"}


def test_generates_query_path_and_header_parameters() -> None:
    endpoint = Endpoint(
        api_schema_id="api_schema_1",
        name="read_item",
        api_style=ApiStyle.REST,
        path="/items/{item_id}",
        method=HttpMethod.GET,
        parameters=[
            Parameter(
                name="item_id",
                location=ParameterLocation.PATH,
                field_type=FieldType.UUID,
                required=True,
            ),
            Parameter(
                name="limit",
                location=ParameterLocation.QUERY,
                field_type=FieldType.INTEGER,
                constraints=[
                    Constraint(
                        constraint_type=ConstraintType.MIN_VALUE,
                        value=1,
                        source="test",
                    ),
                    Constraint(
                        constraint_type=ConstraintType.MAX_VALUE,
                        value=5,
                        source="test",
                    ),
                ],
            ),
            Parameter(
                name="X-Request-ID",
                location=ParameterLocation.HEADER,
                field_type=FieldType.UUID,
            ),
            Parameter(
                name="Authorization",
                location=ParameterLocation.HEADER,
                field_type=FieldType.STRING,
                sensitive=True,
            ),
        ],
    )

    payload = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)
    generated = {parameter.name: parameter for parameter in payload.parameters}

    assert {"item_id", "limit", "X-Request-ID"} == set(generated)
    assert "Authorization" not in generated
    UUID(generated["item_id"].value)
    assert 1 <= generated["limit"].value <= 5
    assert payload.headers == {"X-Request-ID": generated["X-Request-ID"].value}
    assert generated["item_id"].source_field_id is not None
    assert generated["item_id"].valid_against_schema is True


def test_sensitive_header_can_be_supplied_explicitly_and_is_redacted() -> None:
    endpoint = Endpoint(
        api_schema_id="api_schema_1",
        name="auth_read",
        api_style=ApiStyle.REST,
        path="/auth-read",
        method=HttpMethod.GET,
        parameters=[
            Parameter(
                name="Authorization",
                location=ParameterLocation.HEADER,
                field_type=FieldType.STRING,
                sensitive=True,
            )
        ],
    )

    payload = PayloadGenerator(
        seed=123,
        provided_parameters={"Authorization": "synthetic-auth-token"},
    ).generate_for_endpoint(endpoint)

    assert payload.parameters[0].sensitive is True
    assert payload.model_dump(mode="json")["headers"]["Authorization"] == REDACTED_VALUE
    assert payload.model_dump(mode="json")["parameters"][0]["value"] == REDACTED_VALUE


def test_generation_is_deterministic_with_same_seed() -> None:
    endpoint = _complex_post_endpoint()

    first = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)
    second = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)

    assert first.body == second.body
    assert [(parameter.name, parameter.value) for parameter in first.parameters] == [
        (parameter.name, parameter.value) for parameter in second.parameters
    ]


def test_different_seeds_produce_different_valid_values_where_applicable() -> None:
    endpoint = _complex_post_endpoint()

    first = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)
    second = PayloadGenerator(seed=456).generate_for_endpoint(endpoint)

    assert isinstance(first.body, dict)
    assert isinstance(second.body, dict)
    assert first.body["username"] != second.body["username"]
    assert 3 <= len(first.body["username"]) <= 12
    assert 3 <= len(second.body["username"]) <= 12


def test_required_nullable_constraints_enum_formats_object_array_and_unknown() -> None:
    endpoint = _complex_post_endpoint()

    payload = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)

    assert isinstance(payload.body, dict)
    assert {"username", "age", "score", "email", "uid", "website", "created", "created_at"}.issubset(
        payload.body
    )
    assert 3 <= len(payload.body["username"]) <= 12
    assert 18 <= payload.body["age"] <= 99
    assert 1.5 <= payload.body["score"] <= 9.5
    assert payload.body["role"] in {"user", "admin"}
    assert payload.body["email"].endswith("@example.test")
    UUID(payload.body["uid"])
    assert payload.body["website"].startswith("https://example.test/")
    date.fromisoformat(payload.body["created"])
    datetime.fromisoformat(payload.body["created_at"])
    assert payload.body["profile"] is None or isinstance(payload.body["profile"], dict)
    assert isinstance(payload.body["tags"], list)
    assert isinstance(payload.body["tags"][0], str)
    assert isinstance(payload.body["unknown_value"], str)


def test_sensitive_body_field_is_synthetic_and_redacted_in_serialization() -> None:
    endpoint = _complex_post_endpoint()

    payload = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)

    assert isinstance(payload.body, dict)
    assert payload.body["password"].startswith("synthetic-sensitive")
    assert payload.model_dump(mode="json")["body"]["password"] == REDACTED_VALUE


def test_generation_does_not_make_network_calls(monkeypatch) -> None:
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    PayloadGenerator(seed=123).generate_for_endpoint(_complex_post_endpoint())


def _complex_post_endpoint() -> Endpoint:
    return Endpoint(
        api_schema_id="api_schema_1",
        name="create_complex",
        api_style=ApiStyle.REST,
        path="/complex",
        method=HttpMethod.POST,
        request_body=RequestBodyDefinition(
            content_type="application/json",
            required=True,
            root_type=TypeReference(field_type=FieldType.OBJECT),
            fields=[
                FieldDefinition(
                    name="username",
                    field_type=FieldType.STRING,
                    required=True,
                    constraints=[
                        Constraint(
                            constraint_type=ConstraintType.MIN_LENGTH,
                            value=3,
                            source="test",
                        ),
                        Constraint(
                            constraint_type=ConstraintType.MAX_LENGTH,
                            value=12,
                            source="test",
                        ),
                    ],
                ),
                FieldDefinition(
                    name="age",
                    field_type=FieldType.INTEGER,
                    required=True,
                    constraints=[
                        Constraint(
                            constraint_type=ConstraintType.MIN_VALUE,
                            value=18,
                            source="test",
                        ),
                        Constraint(
                            constraint_type=ConstraintType.MAX_VALUE,
                            value=99,
                            source="test",
                        ),
                    ],
                ),
                FieldDefinition(
                    name="score",
                    field_type=FieldType.FLOAT,
                    required=True,
                    constraints=[
                        Constraint(
                            constraint_type=ConstraintType.MIN_VALUE,
                            value=1.5,
                            source="test",
                        ),
                        Constraint(
                            constraint_type=ConstraintType.MAX_VALUE,
                            value=9.5,
                            source="test",
                        ),
                    ],
                ),
                FieldDefinition(name="enabled", field_type=FieldType.BOOLEAN, required=True),
                FieldDefinition(
                    name="role",
                    field_type=FieldType.ENUM,
                    constraints=[
                        Constraint(
                            constraint_type=ConstraintType.ENUM,
                            value=["user", "admin"],
                            source="test",
                        )
                    ],
                ),
                FieldDefinition(name="email", field_type=FieldType.EMAIL, required=True),
                FieldDefinition(name="uid", field_type=FieldType.UUID, required=True),
                FieldDefinition(name="website", field_type=FieldType.URI, required=True),
                FieldDefinition(name="created", field_type=FieldType.DATE, required=True),
                FieldDefinition(name="created_at", field_type=FieldType.DATETIME, required=True),
                FieldDefinition(
                    name="profile",
                    field_type=FieldType.OBJECT,
                    nullable=True,
                    nested_fields=[
                        FieldDefinition(name="display_name", field_type=FieldType.STRING, required=True)
                    ],
                ),
                FieldDefinition(
                    name="tags",
                    field_type=FieldType.ARRAY,
                    array_item_type=TypeReference(field_type=FieldType.STRING),
                ),
                FieldDefinition(name="unknown_value", field_type=FieldType.UNKNOWN),
                FieldDefinition(name="password", field_type=FieldType.STRING, sensitive=True),
            ],
        ),
    )
