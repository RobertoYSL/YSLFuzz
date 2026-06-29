import pytest

from yslfuzz.execution import BindingResolutionError, BindingResolver
from yslfuzz.models import PayloadCandidate, PayloadKind, VariableBinding
from yslfuzz.models.enums import ParameterLocation


def test_variable_binding_binds_known_id_into_path_parameter() -> None:
    payload = _payload()
    binding = VariableBinding(source="id", target="path.user_id")

    updated = BindingResolver().apply(payload, [binding], {"id": "user_123"})

    parameter = updated.parameters[0]
    assert parameter.location == ParameterLocation.PATH
    assert parameter.name == "user_id"
    assert parameter.value == "user_123"


def test_variable_binding_binds_known_id_into_query_parameter() -> None:
    payload = _payload()
    binding = VariableBinding(source="user_id", target="query.user_id")

    updated = BindingResolver().apply(payload, [binding], {"user_id": "user_123"})

    parameter = updated.parameters[0]
    assert parameter.location == ParameterLocation.QUERY
    assert parameter.name == "user_id"
    assert parameter.value == "user_123"


def test_variable_binding_fails_clearly_when_required_value_is_missing() -> None:
    payload = _payload()
    binding = VariableBinding(source="user_id", target="path.user_id")

    with pytest.raises(BindingResolutionError, match="Missing required binding source"):
        BindingResolver().apply(payload, [binding], {})


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id="endpoint_get_user",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        generation_strategy="unit-test",
        seed=1,
    )
