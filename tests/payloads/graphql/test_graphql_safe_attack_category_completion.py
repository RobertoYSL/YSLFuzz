from yslfuzz.discovery.graphql import GraphQLSDLParser
from yslfuzz.models import AttackCategory
from yslfuzz.payloads.graphql import (
    GraphQLAttackPayloadGenerator,
    GraphQLMutationConfig,
    GraphQLPayloadGenerator,
)


def test_graphql_safe_attack_generator_includes_missing_marker_categories_safely() -> None:
    schema = GraphQLSDLParser().parse(
        """
        type Query {
          search(term: String!): String
        }
        """
    )
    valid_payloads = GraphQLPayloadGenerator().generate(schema)
    config = GraphQLMutationConfig(
        include_attack_payloads=True,
        enabled_attack_categories=[
            AttackCategory.SQL_INJECTION,
            AttackCategory.NOSQL_INJECTION,
            AttackCategory.COMMAND_INJECTION,
            AttackCategory.SSRF,
        ],
        max_attack_payloads_per_operation=10,
    )

    payloads = GraphQLAttackPayloadGenerator(config).generate(schema, valid_payloads)
    bodies = " ".join(str(payload.body) for payload in payloads)
    categories = {payload.attack_category for payload in payloads}

    assert AttackCategory.SQL_INJECTION in categories
    assert AttackCategory.NOSQL_INJECTION in categories
    assert AttackCategory.COMMAND_INJECTION in categories
    assert AttackCategory.SSRF in categories
    assert "yslfuzz_graphql_sql_marker" in bodies
    assert "yslfuzz_graphql_nosql_marker" in bodies
    assert "yslfuzz_graphql_command_marker" in bodies
    assert "yslfuzz-ssrf-marker.invalid" in bodies
    assert "' OR" not in bodies.upper()
    assert "$ne" not in bodies
    assert "/bin/" not in bodies
    assert "169.254.169.254" not in bodies
    assert "localhost" not in bodies


def test_graphql_introspection_probe_is_still_explicit_opt_in() -> None:
    schema = GraphQLSDLParser().parse("type Query { ping: String }")
    valid_payloads = GraphQLPayloadGenerator().generate(schema)

    disabled = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(include_attack_payloads=True)
    ).generate(schema, valid_payloads)
    enabled = GraphQLAttackPayloadGenerator(
        GraphQLMutationConfig(
            include_attack_payloads=True,
            allow_introspection_probe=True,
            enabled_attack_categories=[AttackCategory.GRAPHQL_INTROSPECTION_ABUSE],
        )
    ).generate(schema, valid_payloads)

    assert all(
        payload.metadata.get("graphql_mutation_operator") != "attack_introspection_probe"
        for payload in disabled
    )
    assert any(
        payload.metadata.get("graphql_mutation_operator") == "attack_introspection_probe"
        for payload in enabled
    )

