from yslfuzz.discovery.graphql import GraphQLSchemaLoader
from yslfuzz.models.enums import AttackCategory, PayloadKind
from yslfuzz.payloads.graphql import (
    GraphQLAttackPayloadGenerator,
    GraphQLMutationConfig,
    GraphQLPayloadGenerator,
)


def _schema_and_payloads() -> tuple[object, list[object]]:
    schema = GraphQLSchemaLoader().load("examples/graphql/simple_users_schema.graphql")
    payloads = GraphQLPayloadGenerator().generate(schema)
    return schema, payloads


def test_graphql_attack_generator_creates_safe_mvp_probes() -> None:
    schema, payloads = _schema_and_payloads()

    generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(include_attack_payloads=True, max_attack_payloads_per_operation=4),
    ).generate(schema, payloads)
    categories = {payload.attack_category for payload in generated}

    assert AttackCategory.INPUT_VALIDATION in categories
    assert AttackCategory.INFORMATION_DISCLOSURE in categories
    assert AttackCategory.XSS in categories
    assert AttackCategory.MASS_ASSIGNMENT in categories
    assert all(payload.payload_kind == PayloadKind.ATTACK for payload in generated)
    assert "script" not in str([payload.body for payload in generated]).lower()


def test_graphql_attack_generator_does_not_create_auth_bypass_payloads() -> None:
    schema, payloads = _schema_and_payloads()

    generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(
            include_attack_payloads=True,
            enabled_attack_categories=[AttackCategory.BROKEN_ACCESS_CONTROL],
        ),
    ).generate(schema, payloads)

    assert generated == []


def test_graphql_attack_generator_avoids_prohibited_payload_strings() -> None:
    schema, payloads = _schema_and_payloads()
    generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(include_attack_payloads=True, max_attack_payloads_per_operation=4),
    ).generate(schema, payloads)
    serialized = str([payload.body for payload in generated]).lower()

    assert "select " not in serialized
    assert "$ne" not in serialized
    assert "169.254.169.254" not in serialized
    assert "<script" not in serialized


def test_graphql_introspection_probe_disabled_by_default_and_explicit_when_enabled() -> None:
    schema, payloads = _schema_and_payloads()

    default_generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(include_attack_payloads=True),
    ).generate(schema, payloads)
    enabled_generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(include_attack_payloads=True, allow_introspection_probe=True),
    ).generate(schema, payloads)

    assert "__schema" not in str([payload.body for payload in default_generated])
    assert "__schema" in str([payload.body for payload in enabled_generated])


def test_graphql_field_suggestion_probe_generated_when_enabled() -> None:
    schema, payloads = _schema_and_payloads()
    generated = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(
            include_attack_payloads=True,
            allow_field_suggestion_probe=True,
            max_attack_payloads_per_operation=10,
        ),
    ).generate(schema, payloads)

    operators = [p.metadata.get("graphql_mutation_operator") for p in generated]
    assert "attack_field_suggestion_probe" in operators


def test_graphql_boolean_sql_probe_generated_when_enabled() -> None:
    schema, payloads = _schema_and_payloads()
    disabled = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(
            include_attack_payloads=True,
            allow_sql_boolean_probe=False,
            max_attack_payloads_per_operation=10,
        ),
    ).generate(schema, payloads)
    enabled = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(
            include_attack_payloads=True,
            allow_sql_boolean_probe=True,
            max_attack_payloads_per_operation=10,
        ),
    ).generate(schema, payloads)

    assert not any(p.metadata.get("graphql_mutation_operator") == "attack_sql_boolean_probe" for p in disabled)
    assert any(p.metadata.get("graphql_mutation_operator") == "attack_sql_boolean_probe" for p in enabled)

