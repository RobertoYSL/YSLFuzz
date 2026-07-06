from yslfuzz.discovery.graphql import GraphQLEnum, GraphQLSchema, GraphQLTypeKind, GraphQLTypeRef
from yslfuzz.models.enums import PayloadKind
from yslfuzz.payloads.graphql.mutation_operators import (
    GraphQLMutationContext,
    boundary_mutations,
    invalid_mutations,
    mutated_mutations,
)


def ref(name: str, kind: GraphQLTypeKind = GraphQLTypeKind.SCALAR) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=kind, name=name)


def non_null(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.NON_NULL, of_type=type_ref)


def context(type_ref: GraphQLTypeRef, value: object) -> GraphQLMutationContext:
    return GraphQLMutationContext(
        variable_name="value",
        type_ref=type_ref,
        original_value=value,
        target_path=("value",),
        schema=GraphQLSchema(
            source_format="sdl",
            enums=[GraphQLEnum(name="Role", enum_values=["USER", "ADMIN"])],
        ),
    )


def test_string_boundary_mutation_generation() -> None:
    values = [mutation.value for mutation in boundary_mutations(context(ref("String"), "x"), True)]

    assert "" in values
    assert "yslfuzz_graphql_boundary_string" in values


def test_id_int_float_boolean_boundary_mutation_generation() -> None:
    assert "yslfuzz-id-boundary" in [
        mutation.value for mutation in boundary_mutations(context(ref("ID"), "1"), True)
    ]
    assert -1 in [mutation.value for mutation in boundary_mutations(context(ref("Int"), 1), True)]
    assert -1.0 in [
        mutation.value for mutation in boundary_mutations(context(ref("Float"), 1.0), True)
    ]
    assert False in [
        mutation.value for mutation in boundary_mutations(context(ref("Boolean"), True), True)
    ]


def test_enum_valid_alternate_mutation() -> None:
    enum_ref = ref("Role", GraphQLTypeKind.ENUM)

    assert boundary_mutations(context(enum_ref, "USER"), True)[0].value == "ADMIN"
    assert mutated_mutations(context(enum_ref, "USER"), True)[0].value == "ADMIN"


def test_invalid_enum_mutation_only_when_explicitly_allowed() -> None:
    enum_ref = ref("Role", GraphQLTypeKind.ENUM)

    assert invalid_mutations(
        context(enum_ref, "USER"),
        allow_null_mutations=True,
        allow_type_confusion=True,
        allow_invalid_enum_values=False,
    ) == []
    assert invalid_mutations(
        context(enum_ref, "USER"),
        allow_null_mutations=True,
        allow_type_confusion=True,
        allow_invalid_enum_values=True,
    )[0].value == "YSLFUZZ_INVALID_ENUM"


def test_list_null_and_type_confusion_mutations() -> None:
    list_ref = GraphQLTypeRef(kind=GraphQLTypeKind.LIST, of_type=ref("String"))

    assert [] in [mutation.value for mutation in boundary_mutations(context(list_ref, ["x"]), True)]
    assert invalid_mutations(
        context(non_null(ref("String")), "x"),
        allow_null_mutations=True,
        allow_type_confusion=False,
        allow_invalid_enum_values=False,
    )[0].value is None
    assert invalid_mutations(
        context(ref("String"), "x"),
        allow_null_mutations=False,
        allow_type_confusion=True,
        allow_invalid_enum_values=False,
    )[0].payload_kind == PayloadKind.INVALID
