from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Constraint,
    ConstraintType,
    Endpoint,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    PayloadCandidate,
    PayloadKind,
    RequestBodyDefinition,
)
from yslfuzz.payloads import MutationConfig, MutationEngine, PayloadGenerator


def test_mutation_engine_returns_payload_candidates_with_lineage_strategy_and_metadata() -> None:
    endpoint, payload = _payload()

    mutations = _mutations(endpoint, payload)

    assert mutations
    assert all(isinstance(mutation, PayloadCandidate) for mutation in mutations)
    assert all(mutation.parent_payload_id == payload.payload_id for mutation in mutations)
    assert all(mutation.generation_strategy.startswith("mutation_") for mutation in mutations)
    assert all(mutation.metadata["mutation_name"] for mutation in mutations)
    assert all(mutation.metadata["target_field"] for mutation in mutations)
    assert all(mutation.metadata["target_location"] for mutation in mutations)
    assert all(mutation.metadata["original_field_type"] for mutation in mutations)
    assert all(mutation.metadata["mutated_payload_kind"] for mutation in mutations)
    assert all(mutation.metadata["safety_label"] for mutation in mutations)


def test_sensitive_fields_are_skipped_by_default_and_only_mutated_when_enabled() -> None:
    endpoint, payload = _payload()

    default_mutations = _mutations(endpoint, payload)
    sensitive_mutations = _mutations(
        endpoint,
        payload,
        MutationConfig(include_sensitive_fields=True, max_mutations_per_payload=100, max_mutations_per_field=20),
    )

    assert "password" not in {mutation.metadata["target_field"] for mutation in default_mutations}
    assert "Authorization" not in {mutation.metadata["target_field"] for mutation in default_mutations}
    assert {"password", "Authorization"}.issubset(
        {mutation.metadata["target_field"] for mutation in sensitive_mutations}
    )
    password_mutation = next(
        mutation for mutation in sensitive_mutations if mutation.metadata["target_field"] == "password"
    )
    assert password_mutation.model_dump(mode="json")["body"]["password"] == "[REDACTED]"


def test_string_mutations_include_empty_boundary_unicode_and_marker_variants() -> None:
    endpoint, payload = _payload()
    mutations = _field_mutations(endpoint, payload, "name")
    values = {mutation.body["name"] for mutation in mutations if isinstance(mutation.body, dict)}

    assert "" in values
    assert "mmm" in values
    assert "x" * 8 in values
    assert "yslfuzz_unicode_probe_å" in values
    assert "yslfuzz_probe_string" in values
    assert "   " in values


def test_integer_mutations_include_min_max_boundary_and_type_confusion() -> None:
    endpoint, payload = _payload()
    mutations = _field_mutations(endpoint, payload, "age")
    values = {mutation.body["age"] for mutation in mutations if isinstance(mutation.body, dict)}

    assert {18, 30, 0, -1, 31, 17}.issubset(values)
    assert any(isinstance(value, str) for value in values)


def test_float_mutations_include_min_max_boundary_and_type_confusion() -> None:
    endpoint, payload = _payload()
    mutations = _field_mutations(endpoint, payload, "score")
    values = {mutation.body["score"] for mutation in mutations if isinstance(mutation.body, dict)}

    assert {1.5, 9.5, 0.0, -1.0, 10.5, 0.5}.issubset(values)
    assert any(isinstance(value, str) for value in values)


def test_boolean_mutations_include_flip_and_optional_type_confusion() -> None:
    endpoint, payload = _payload()
    mutations = _field_mutations(endpoint, payload, "enabled")
    values = {mutation.body["enabled"] for mutation in mutations if isinstance(mutation.body, dict)}

    assert isinstance(payload.body, dict)
    assert (not bool(payload.body["enabled"])) in values
    assert str(bool(payload.body["enabled"])).lower() in values


def test_nullable_and_required_non_null_null_mutations_are_supported() -> None:
    endpoint, payload = _payload()
    optional_values = [
        mutation
        for mutation in _field_mutations(endpoint, payload, "nickname")
        if isinstance(mutation.body, dict) and mutation.body["nickname"] is None
    ]
    required_values = [
        mutation
        for mutation in _field_mutations(endpoint, payload, "name")
        if isinstance(mutation.body, dict) and mutation.body["name"] is None
    ]

    assert optional_values
    assert required_values
    assert required_values[0].payload_kind in {PayloadKind.INVALID, PayloadKind.BOUNDARY}


def test_enum_fields_stay_allowed_by_default_and_invalid_enum_requires_opt_in() -> None:
    endpoint, payload = _payload()
    default_values = {
        mutation.body["role"]
        for mutation in _field_mutations(endpoint, payload, "role")
        if isinstance(mutation.body, dict)
    }
    invalid_values = {
        mutation.body["role"]
        for mutation in _field_mutations(
            endpoint,
            payload,
            "role",
            MutationConfig(
                allow_invalid_enum_values=True,
                max_mutations_per_payload=100,
                max_mutations_per_field=20,
                random_seed=1,
            ),
        )
        if isinstance(mutation.body, dict)
    }

    assert default_values <= {"user", "admin"}
    assert "yslfuzz_invalid_enum" not in default_values
    assert "yslfuzz_invalid_enum" in invalid_values


def test_email_uuid_and_uri_mutations_are_safe() -> None:
    endpoint, payload = _payload()
    email_values = _body_values(_field_mutations(endpoint, payload, "email"), "email")
    uuid_values = _body_values(_field_mutations(endpoint, payload, "uid"), "uid")
    uri_values = _body_values(_field_mutations(endpoint, payload, "website"), "website")

    assert "mutated-user@example.test" in email_values
    assert "yslfuzz-email-probe" in email_values
    assert "00000000-0000-4000-8000-000000000000" in uuid_values
    assert "yslfuzz-uuid-probe" in uuid_values
    assert "https://example.test/yslfuzz-probe" in uri_values
    assert "https://yslfuzz-uri-probe.invalid/resource" in uri_values
    assert all("169.254.169.254" not in str(value) for value in uri_values)


def test_object_and_array_mutations_are_bounded() -> None:
    endpoint, payload = _payload()
    profile_values = _body_values(_field_mutations(endpoint, payload, "profile"), "profile")
    tags_values = _body_values(_field_mutations(endpoint, payload, "tags"), "tags")

    assert any(isinstance(value, dict) and value.get("website") == "yslfuzz_probe_string" for value in profile_values)
    assert [] in tags_values
    assert ["yslfuzz_array_item"] in tags_values
    assert ["yslfuzz_array_item_1", "yslfuzz_array_item_2", "yslfuzz_array_item_3"] in tags_values


def test_limits_and_payload_kind_filters_are_respected() -> None:
    endpoint, payload = _payload()

    mutations = _mutations(
        endpoint,
        payload,
        MutationConfig(
            enabled_payload_kinds=[PayloadKind.BOUNDARY],
            max_mutations_per_payload=3,
            max_mutations_per_field=1,
            random_seed=1,
        ),
    )

    assert len(mutations) == 3
    assert {mutation.payload_kind for mutation in mutations} == {PayloadKind.BOUNDARY}
    counts: dict[str, int] = {}
    for mutation in mutations:
        counts[mutation.metadata["target_field"]] = counts.get(mutation.metadata["target_field"], 0) + 1
    assert max(counts.values()) == 1


def test_attack_category_filters_attack_classified_mutations() -> None:
    endpoint, payload = _payload()

    blocked = _mutations(
        endpoint,
        payload,
        MutationConfig(
            enabled_payload_kinds=[PayloadKind.ATTACK],
            enabled_attack_categories=[],
            max_mutations_per_payload=100,
            max_mutations_per_field=20,
        ),
    )
    allowed = _mutations(
        endpoint,
        payload,
        MutationConfig(
            enabled_payload_kinds=[PayloadKind.ATTACK],
            enabled_attack_categories=[AttackCategory.XSS],
            max_mutations_per_payload=100,
            max_mutations_per_field=20,
        ),
    )

    assert blocked == []
    assert allowed
    assert {mutation.attack_category for mutation in allowed} == {AttackCategory.XSS}


def test_same_seed_is_deterministic_and_different_seed_can_change_ordering() -> None:
    endpoint, payload = _payload()

    first = [_signature(mutation) for mutation in _mutations(endpoint, payload, MutationConfig(random_seed=1))]
    second = [_signature(mutation) for mutation in _mutations(endpoint, payload, MutationConfig(random_seed=1))]
    third = [_signature(mutation) for mutation in _mutations(endpoint, payload, MutationConfig(random_seed=2))]

    assert first == second
    assert first != third


def test_mutation_generation_does_not_make_network_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)
    endpoint, payload = _payload()

    assert _mutations(endpoint, payload)


def _field_mutations(
    endpoint: Endpoint,
    payload: PayloadCandidate,
    field_name: str,
    config: MutationConfig | None = None,
) -> list[PayloadCandidate]:
    return [
        mutation
        for mutation in _mutations(
            endpoint,
            payload,
            config
            or MutationConfig(max_mutations_per_payload=200, max_mutations_per_field=20, random_seed=1),
        )
        if mutation.metadata["target_field"] == field_name
    ]


def _mutations(
    endpoint: Endpoint,
    payload: PayloadCandidate,
    config: MutationConfig | None = None,
) -> list[PayloadCandidate]:
    return MutationEngine(config or MutationConfig(max_mutations_per_payload=100, max_mutations_per_field=20)).mutate(
        endpoint,
        payload,
    )


def _body_values(mutations: list[PayloadCandidate], field_name: str) -> list[object]:
    return [mutation.body[field_name] for mutation in mutations if isinstance(mutation.body, dict)]


def _signature(payload: PayloadCandidate) -> tuple[str, str, str]:
    return (
        payload.payload_kind.value,
        payload.metadata["target_field"],
        payload.metadata["mutation_name"],
    )


def _payload() -> tuple[Endpoint, PayloadCandidate]:
    endpoint = _endpoint()
    payload = PayloadGenerator(seed=1, provided_parameters={"Authorization": "synthetic-auth"}).generate_for_endpoint(endpoint)
    assert isinstance(payload.body, dict)
    payload.body["profile"] = {"website": "https://example.test/profile"}
    return endpoint, payload


def _endpoint() -> Endpoint:
    return Endpoint(
        endpoint_id="endpoint_mutation",
        api_schema_id="api_schema_1",
        name="createUser",
        api_style=ApiStyle.REST,
        path="/users/{uid}",
        method=HttpMethod.POST,
        parameters=[
            Parameter(name="uid", location=ParameterLocation.PATH, field_type=FieldType.UUID, required=True),
            Parameter(name="limit", location=ParameterLocation.QUERY, field_type=FieldType.INTEGER),
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
                FieldDefinition(
                    name="name",
                    field_type=FieldType.STRING,
                    required=True,
                    constraints=[
                        Constraint(constraint_type=ConstraintType.MIN_LENGTH, value=3, source="test"),
                        Constraint(constraint_type=ConstraintType.MAX_LENGTH, value=8, source="test"),
                    ],
                ),
                FieldDefinition(name="nickname", field_type=FieldType.STRING, nullable=True),
                FieldDefinition(
                    name="age",
                    field_type=FieldType.INTEGER,
                    constraints=[
                        Constraint(constraint_type=ConstraintType.MIN_VALUE, value=18, source="test"),
                        Constraint(constraint_type=ConstraintType.MAX_VALUE, value=30, source="test"),
                    ],
                ),
                FieldDefinition(
                    name="score",
                    field_type=FieldType.FLOAT,
                    constraints=[
                        Constraint(constraint_type=ConstraintType.MIN_VALUE, value=1.5, source="test"),
                        Constraint(constraint_type=ConstraintType.MAX_VALUE, value=9.5, source="test"),
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
                FieldDefinition(name="email", field_type=FieldType.EMAIL),
                FieldDefinition(name="uid", field_type=FieldType.UUID),
                FieldDefinition(name="website", field_type=FieldType.URI),
                FieldDefinition(
                    name="profile",
                    field_type=FieldType.OBJECT,
                    nested_fields=[FieldDefinition(name="website", field_type=FieldType.URI)],
                ),
                FieldDefinition(name="tags", field_type=FieldType.ARRAY),
                FieldDefinition(name="password", field_type=FieldType.STRING, sensitive=True),
            ],
        ),
    )
