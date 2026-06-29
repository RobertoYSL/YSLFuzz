import json

from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Constraint,
    ConstraintType,
    FieldDefinition,
    FieldType,
    HttpMethod,
    Parameter,
    ParameterLocation,
    PayloadKind,
    RequestBodyDefinition,
)
from yslfuzz.models.schema import Endpoint
from yslfuzz.payloads import AttackGenerationConfig, AttackPayloadGenerator, PayloadGenerator


def test_attack_payload_generator_creates_attack_payload_candidates() -> None:
    attacks = _attacks([AttackCategory.SQL_INJECTION])

    assert attacks
    assert all(payload.payload_kind == PayloadKind.ATTACK for payload in attacks)


def test_attack_category_is_always_set_for_attack_payloads() -> None:
    attacks = _attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS])

    assert all(payload.attack_category is not None for payload in attacks)


def test_parent_payload_id_references_original_valid_payload() -> None:
    endpoint = _endpoint()
    valid = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)

    attacks = _generator([AttackCategory.SQL_INJECTION]).generate(endpoint, valid)

    assert all(payload.parent_payload_id == valid.payload_id for payload in attacks)


def test_generation_strategy_and_metadata_are_populated() -> None:
    attack = _attacks([AttackCategory.SQL_INJECTION])[0]

    assert attack.generation_strategy.startswith("attack_sql_injection")
    assert attack.metadata["target_field"]
    assert attack.metadata["target_location"]
    assert attack.metadata["mutation_name"]
    assert attack.metadata["safety_label"]
    assert attack.metadata["non_executing"] is True


def test_sql_injection_probes_are_generated_for_string_fields() -> None:
    attack = _first_attack(AttackCategory.SQL_INJECTION, "name")

    assert "yslfuzz_sqli_probe" in attack.body["name"]


def test_nosql_injection_probes_are_generated_for_object_like_body_fields() -> None:
    attack = _first_attack(AttackCategory.NOSQL_INJECTION, "profile")

    assert attack.body["profile"]["yslfuzz_nosql_probe"] == "marker"


def test_command_injection_probes_are_inert_marker_based() -> None:
    attack = _first_attack(AttackCategory.COMMAND_INJECTION, "name")

    assert attack.body["name"] == "yslfuzz_cmd_probe"
    assert "rm " not in attack.body["name"]
    assert "/bin/" not in attack.body["name"]


def test_ssrf_probes_use_safe_reserved_non_production_targets() -> None:
    attack = _first_attack(AttackCategory.SSRF, "website")

    assert attack.body["website"].endswith(".invalid/resource")
    assert "169.254.169.254" not in attack.body["website"]


def test_xss_probes_are_inert_and_do_not_use_script_tags() -> None:
    attack = _first_attack(AttackCategory.XSS, "name")

    assert "yslfuzz_xss_probe" in attack.body["name"]
    assert "<script" not in attack.body["name"].lower()


def test_mass_assignment_probes_add_controlled_extra_fields() -> None:
    attack = _first_attack(AttackCategory.MASS_ASSIGNMENT, "profile")

    assert attack.body["profile"]["yslfuzz_probe"] == "mass_assignment_marker"
    assert attack.body["profile"]["yslfuzz_extra_role"] == "controlled_marker"


def test_broken_access_control_probes_are_metadata_oriented_and_non_executing() -> None:
    attack = _first_attack(AttackCategory.BROKEN_ACCESS_CONTROL, "user_id")

    assert attack.attack_category == AttackCategory.BROKEN_ACCESS_CONTROL
    assert attack.metadata["non_executing"] is True
    assert "yslfuzz_bac_probe" in json.dumps(attack.model_dump(mode="json"))


def test_input_validation_probes_include_boundary_and_type_confusion_cases() -> None:
    attacks = _attacks([AttackCategory.INPUT_VALIDATION], max_payloads_per_endpoint=20)
    encoded = json.dumps([payload.model_dump(mode="json") for payload in attacks])

    assert "yslfuzz_input_validation_probe" in encoded
    assert "-1" in encoded


def test_information_disclosure_probes_are_marker_oriented_and_non_executing() -> None:
    attack = _first_attack(AttackCategory.INFORMATION_DISCLOSURE, "name")

    assert attack.body["name"] == "yslfuzz_info_disclosure_probe"
    assert attack.metadata["non_executing"] is True


def test_enum_fields_stay_within_enum_unless_input_validation() -> None:
    attacks = _attacks(
        [AttackCategory.SQL_INJECTION, AttackCategory.XSS, AttackCategory.INPUT_VALIDATION],
        max_payloads_per_endpoint=30,
    )
    enum_attacks = [payload for payload in attacks if payload.metadata["target_field"] == "role"]

    assert enum_attacks
    assert {payload.attack_category for payload in enum_attacks} == {AttackCategory.INPUT_VALIDATION}


def test_sensitive_fields_are_not_targeted_by_default() -> None:
    attacks = _attacks([AttackCategory.SQL_INJECTION], max_payloads_per_endpoint=30)

    assert "password" not in {payload.metadata["target_field"] for payload in attacks}


def test_sensitive_fields_can_only_be_targeted_when_explicitly_enabled() -> None:
    attacks = _attacks(
        [AttackCategory.SQL_INJECTION],
        include_sensitive_fields=True,
        max_payloads_per_endpoint=30,
    )

    assert "password" in {payload.metadata["target_field"] for payload in attacks}
    password_attack = next(payload for payload in attacks if payload.metadata["target_field"] == "password")
    assert password_attack.model_dump(mode="json")["body"]["password"] == "[REDACTED]"


def test_max_payloads_per_endpoint_is_respected() -> None:
    assert len(_attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS], max_payloads_per_endpoint=3)) == 3


def test_max_payloads_per_field_is_respected() -> None:
    attacks = _attacks(
        [AttackCategory.SQL_INJECTION, AttackCategory.XSS, AttackCategory.INFORMATION_DISCLOSURE],
        max_payloads_per_field=1,
        max_payloads_per_endpoint=50,
    )
    counts: dict[str, int] = {}
    for attack in attacks:
        counts[attack.metadata["target_field"]] = counts.get(attack.metadata["target_field"], 0) + 1

    assert counts
    assert max(counts.values()) == 1


def test_enabled_categories_filter_output() -> None:
    attacks = _attacks([AttackCategory.SSRF])

    assert attacks
    assert {payload.attack_category for payload in attacks} == {AttackCategory.SSRF}


def test_deterministic_output_with_same_seed() -> None:
    first = [_signature(payload) for payload in _attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS], seed=7)]
    second = [_signature(payload) for payload in _attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS], seed=7)]

    assert first == second


def test_different_seed_can_change_ordering() -> None:
    first = [_signature(payload) for payload in _attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS], seed=1)]
    second = [_signature(payload) for payload in _attacks([AttackCategory.SQL_INJECTION, AttackCategory.XSS], seed=2)]

    assert first != second


def test_attack_generation_does_not_make_external_network_calls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    monkeypatch.setattr("socket.create_connection", fail_network_call)

    assert _attacks([AttackCategory.SQL_INJECTION])


def _first_attack(category: AttackCategory, target_field: str):
    return next(
        payload
        for payload in _attacks([category], max_payloads_per_endpoint=30)
        if payload.metadata["target_field"] == target_field
    )


def _attacks(
    categories: list[AttackCategory],
    *,
    seed: int = 1,
    max_payloads_per_endpoint: int = 10,
    max_payloads_per_field: int = 2,
    include_sensitive_fields: bool = False,
):
    endpoint = _endpoint()
    valid = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)
    return _generator(
        categories,
        seed=seed,
        max_payloads_per_endpoint=max_payloads_per_endpoint,
        max_payloads_per_field=max_payloads_per_field,
        include_sensitive_fields=include_sensitive_fields,
    ).generate(endpoint, valid)


def _generator(
    categories: list[AttackCategory],
    *,
    seed: int = 1,
    max_payloads_per_endpoint: int = 10,
    max_payloads_per_field: int = 2,
    include_sensitive_fields: bool = False,
) -> AttackPayloadGenerator:
    return AttackPayloadGenerator(
        AttackGenerationConfig(
            enabled_categories=categories,
            seed=seed,
            max_payloads_per_endpoint=max_payloads_per_endpoint,
            max_payloads_per_field=max_payloads_per_field,
            include_sensitive_fields=include_sensitive_fields,
        )
    )


def _signature(payload) -> tuple[str, str, str]:  # type: ignore[no-untyped-def]
    return (
        payload.attack_category.value,
        payload.metadata["target_field"],
        payload.metadata["mutation_name"],
    )


def _endpoint() -> Endpoint:
    return Endpoint(
        api_schema_id="api_schema_1",
        name="createUser",
        api_style=ApiStyle.REST,
        path="/users/{user_id}",
        method=HttpMethod.POST,
        parameters=[
            Parameter(name="user_id", location=ParameterLocation.PATH, field_type=FieldType.UUID),
            Parameter(name="limit", location=ParameterLocation.QUERY, field_type=FieldType.INTEGER),
            Parameter(name="X-Trace-ID", location=ParameterLocation.HEADER, field_type=FieldType.STRING),
        ],
        request_body=RequestBodyDefinition(
            content_type="application/json",
            fields=[
                FieldDefinition(name="name", field_type=FieldType.STRING),
                FieldDefinition(name="website", field_type=FieldType.URI),
                FieldDefinition(name="enabled", field_type=FieldType.BOOLEAN),
                FieldDefinition(name="score", field_type=FieldType.FLOAT),
                FieldDefinition(name="profile", field_type=FieldType.OBJECT),
                FieldDefinition(name="tags", field_type=FieldType.ARRAY),
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
                FieldDefinition(name="password", field_type=FieldType.STRING, sensitive=True),
            ],
        ),
    )
