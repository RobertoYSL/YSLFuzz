from yslfuzz.discovery.graphql import GraphQLEnum, GraphQLSchema, GraphQLTypeKind, GraphQLTypeRef
from yslfuzz.payloads.graphql import GraphQLScalarValueGenerator


def ref(name: str) -> GraphQLTypeRef:
    return GraphQLTypeRef(kind=GraphQLTypeKind.SCALAR, name=name)


def test_scalar_generator_returns_deterministic_builtin_values() -> None:
    schema = GraphQLSchema(source_format="sdl")
    generator = GraphQLScalarValueGenerator()

    assert generator.generate(ref("ID"), schema) == "yslfuzz-id-001"
    assert generator.generate(ref("String"), schema) == "yslfuzz-string"
    assert generator.generate(ref("Int"), schema) == 1
    assert generator.generate(ref("Float"), schema) == 1.0
    assert generator.generate(ref("Boolean"), schema) is True


def test_scalar_generator_handles_custom_scalar_conservatively() -> None:
    schema = GraphQLSchema(source_format="sdl")

    assert GraphQLScalarValueGenerator().generate(ref("DateTime"), schema) == "yslfuzz-string"


def test_scalar_generator_uses_safe_email_for_email_like_scalar() -> None:
    schema = GraphQLSchema(source_format="sdl")

    assert GraphQLScalarValueGenerator().generate(ref("Email"), schema) == "yslfuzz@example.invalid"


def test_enum_generation_chooses_first_allowed_value_deterministically() -> None:
    schema = GraphQLSchema(
        source_format="sdl",
        enums=[GraphQLEnum(name="UserRole", enum_values=["USER", "ADMIN"])],
    )
    enum_ref = GraphQLTypeRef(kind=GraphQLTypeKind.ENUM, name="UserRole")

    assert GraphQLScalarValueGenerator().generate(enum_ref, schema) == "USER"
