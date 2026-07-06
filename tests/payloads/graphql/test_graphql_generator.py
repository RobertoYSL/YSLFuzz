from yslfuzz.discovery.graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLOperation,
    GraphQLOperationType,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
    GraphQLTypeRef,
)
from yslfuzz.models.enums import PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.payloads.graphql import GraphQLPayloadConfig, GraphQLPayloadGenerator


def scalar_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=name)


def object_ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.OBJECT, name=name)


def non_null(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.NON_NULL, of_type=type_ref)


def schema() -> GraphQLSchema:
    return GraphQLSchema(
        source_format="sdl",
        object_types=[
            GraphQLType(
                name="User",
                fields=[
                    GraphQLField(name="id", type_ref=scalar_ref("ID")),
                    GraphQLField(name="email", type_ref=scalar_ref("String")),
                ],
            )
        ],
        operations=[
            GraphQLOperation(
                name="user",
                operation_type=GraphQLOperationType.QUERY,
                type_ref=object_ref("User"),
                arguments=[GraphQLArgument(name="id", type_ref=non_null(scalar_ref("ID")))],
            ),
            GraphQLOperation(
                name="createUser",
                operation_type=GraphQLOperationType.MUTATION,
                type_ref=object_ref("User"),
            ),
            GraphQLOperation(
                name="events",
                operation_type=GraphQLOperationType.SUBSCRIPTION,
                type_ref=object_ref("User"),
            ),
        ],
    )


def test_payload_generator_creates_valid_payload_candidates() -> None:
    payloads = GraphQLPayloadGenerator().generate(schema())

    assert len(payloads) == 2
    assert all(isinstance(payload, PayloadCandidate) for payload in payloads)
    assert all(payload.payload_kind == PayloadKind.VALID for payload in payloads)
    assert payloads[0].body == {
        "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }",
        "variables": {"id": "yslfuzz-id-001"},
        "operationName": "YSLFuzzUser",
    }


def test_payload_generator_stores_graphql_metadata() -> None:
    test_schema = schema()
    payload = GraphQLPayloadGenerator().generate(test_schema)[0]

    assert payload.metadata["api_style"] == "GRAPHQL"
    assert payload.metadata["graphql_operation_name"] == "YSLFuzzUser"
    assert payload.metadata["graphql_operation_type"] == "query"
    assert payload.metadata["graphql_return_type"] == "User"
    assert payload.metadata["graphql_variable_names"] == ["id"]
    assert payload.metadata["graphql_selection_depth"] == 1
    assert payload.metadata["graphql_source_schema_id"] == test_schema.schema_id
    assert payload.metadata["graphql_payload_generation_version"] == "0.1.0"
    assert payload.metadata["execution_enabled"] is False


def test_payload_generator_is_deterministic_for_same_config_and_schema() -> None:
    test_schema = schema()
    config = GraphQLPayloadConfig(random_seed=123)

    first = [payload.body for payload in GraphQLPayloadGenerator(config).generate(test_schema)]
    second = [payload.body for payload in GraphQLPayloadGenerator(config).generate(test_schema)]

    assert first == second


def test_payload_generator_respects_max_operations() -> None:
    payloads = GraphQLPayloadGenerator(GraphQLPayloadConfig(max_operations=1)).generate(schema())

    assert len(payloads) == 1


def test_payload_generator_can_generate_queries_only() -> None:
    payloads = GraphQLPayloadGenerator(
        GraphQLPayloadConfig(include_queries=True, include_mutations=False),
    ).generate(schema())

    assert [payload.metadata["graphql_operation_type"] for payload in payloads] == ["query"]


def test_payload_generator_can_generate_mutations_only() -> None:
    payloads = GraphQLPayloadGenerator(
        GraphQLPayloadConfig(include_queries=False, include_mutations=True),
    ).generate(schema())

    assert [payload.metadata["graphql_operation_type"] for payload in payloads] == ["mutation"]


def test_payload_generator_does_not_generate_subscriptions_by_default() -> None:
    payloads = GraphQLPayloadGenerator().generate(schema())

    assert "subscription" not in {
        payload.metadata["graphql_operation_type"] for payload in payloads
    }
