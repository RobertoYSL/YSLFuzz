from yslfuzz.discovery.graphql import GraphQLSchemaLoader
from yslfuzz.models.enums import PayloadKind
from yslfuzz.payloads.graphql import GraphQLMutationConfig, GraphQLMutationEngine, GraphQLPayloadGenerator


def _schema_and_payloads() -> tuple[object, list[object]]:
    schema = GraphQLSchemaLoader().load("examples/graphql/simple_users_schema.graphql")
    payloads = GraphQLPayloadGenerator().generate(schema)
    return schema, payloads


def test_graphql_mutation_engine_preserves_lineage_and_metadata() -> None:
    schema, payloads = _schema_and_payloads()
    generated = GraphQLMutationEngine(
        GraphQLMutationConfig(include_boundary_payloads=True, max_mutations_per_payload=1),
    ).mutate(schema, payloads)

    assert generated
    assert generated[0].payload_id != payloads[0].payload_id
    assert generated[0].parent_payload_id == payloads[0].payload_id
    assert generated[0].payload_kind == PayloadKind.BOUNDARY
    assert generated[0].metadata["api_style"] == "GRAPHQL"
    assert generated[0].metadata["graphql_mutation_operator"]
    assert generated[0].metadata["graphql_target_variable"]
    assert generated[0].metadata["safety_label"]


def test_graphql_mutation_engine_respects_limits_and_is_deterministic() -> None:
    schema, payloads = _schema_and_payloads()
    config = GraphQLMutationConfig(
        include_boundary_payloads=True,
        max_mutations_per_payload=1,
        max_mutations_per_variable=1,
        random_seed=123,
    )

    first = GraphQLMutationEngine(config).mutate(schema, payloads)
    second = GraphQLMutationEngine(config).mutate(schema, payloads)

    assert len(first) <= len(payloads)
    assert [payload.body for payload in first] == [payload.body for payload in second]


def test_graphql_mutation_engine_generates_input_object_shape_mutations() -> None:
    schema, payloads = _schema_and_payloads()
    create_user_payloads = [
        payload
        for payload in payloads
        if payload.metadata["graphql_operation_field_name"] == "createUser"
    ]

    generated = GraphQLMutationEngine(
        GraphQLMutationConfig(
            include_invalid_payloads=True,
            max_mutations_per_payload=10,
            max_mutations_per_variable=10,
        ),
    ).mutate(schema, create_user_payloads)
    operators = {payload.metadata["graphql_mutation_operator"] for payload in generated}

    assert "input_object_extra_field" in operators
    assert "input_object_missing_required_field" in operators


def test_graphql_mutation_engine_skips_sensitive_variables_by_default() -> None:
    schema, payloads = _schema_and_payloads()
    payload = payloads[0].model_copy(deep=True)
    payload.body["variables"]["password"] = "secret"
    payload.metadata["graphql_variable_names"].append("password")

    generated = GraphQLMutationEngine(
        GraphQLMutationConfig(include_boundary_payloads=True),
    ).mutate(schema, [payload])

    assert all(payload.metadata.get("graphql_target_variable") != "password" for payload in generated)
