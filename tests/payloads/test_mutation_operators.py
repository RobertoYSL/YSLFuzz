from yslfuzz.models import FieldType, ParameterLocation, PayloadKind
from yslfuzz.payloads import MutationContext, default_mutation_operators


def test_default_mutation_operators_declare_required_metadata() -> None:
    operators = default_mutation_operators()

    assert operators
    assert all(operator.name for operator in operators)
    assert all(operator.description for operator in operators)
    assert all(operator.supported_field_types for operator in operators)
    assert all(operator.supported_locations for operator in operators)
    assert all(operator.safe_label for operator in operators)
    assert all(operator.risk_level for operator in operators)


def test_mutation_operator_apply_returns_mutated_value() -> None:
    operator = next(operator for operator in default_mutation_operators() if operator.name == "string_empty")

    value = operator.apply(
        MutationContext(
            field_name="name",
            field_type=FieldType.STRING,
            value="alice",
            constraints={},
        )
    )

    assert value == ""
    assert operator.output_payload_kind == PayloadKind.BOUNDARY
    assert operator.applies_to(FieldType.STRING, ParameterLocation.BODY)
