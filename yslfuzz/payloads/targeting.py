"""Attack payload target discovery."""

from dataclasses import dataclass
from typing import Any

from yslfuzz.models.base import is_sensitive_key
from yslfuzz.models.enums import ConstraintType, FieldType, ParameterLocation
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Constraint, Endpoint, FieldDefinition


@dataclass(frozen=True)
class AttackTarget:
    """A field or parameter that can be safely targeted by an attack template."""

    name: str
    location: ParameterLocation
    field_type: FieldType
    value: Any
    source_field_id: str | None
    sensitive: bool
    constraints: tuple[Constraint, ...] = ()

    @property
    def target_path(self) -> str:
        return f"{self.location.value.lower()}.{self.name}"


class AttackTargetSelector:
    """Find targetable body fields and parameters for attack payload generation."""

    def select(
        self,
        endpoint: Endpoint,
        payload: PayloadCandidate,
        include_sensitive_fields: bool = False,
    ) -> list[AttackTarget]:
        """Return deterministic attack targets from endpoint schema and a valid payload."""
        targets: list[AttackTarget] = []
        field_map = self._body_field_map(endpoint)
        if isinstance(payload.body, dict):
            for name in sorted(payload.body):
                field = field_map.get(name)
                field_type = field.field_type if field is not None else self._infer_field_type(payload.body[name])
                sensitive = (field.sensitive if field is not None else False) or is_sensitive_key(name)
                if self._allowed_target(ParameterLocation.BODY, name, sensitive, include_sensitive_fields):
                    targets.append(
                        AttackTarget(
                            name=name,
                            location=ParameterLocation.BODY,
                            field_type=field_type,
                            value=payload.body[name],
                            source_field_id=field.field_id if field is not None else None,
                            sensitive=sensitive,
                            constraints=tuple(field.constraints if field is not None else []),
                        )
                    )

        parameter_schema = {parameter.name: parameter for parameter in endpoint.parameters}
        for parameter in sorted(payload.parameters, key=lambda item: (item.location.value, item.name)):
            schema_parameter = parameter_schema.get(parameter.name)
            sensitive = parameter.sensitive or (schema_parameter.sensitive if schema_parameter else False)
            if not self._allowed_target(parameter.location, parameter.name, sensitive, include_sensitive_fields):
                continue
            targets.append(
                AttackTarget(
                    name=parameter.name,
                    location=parameter.location,
                    field_type=parameter.field_type,
                    value=parameter.value,
                    source_field_id=parameter.source_field_id,
                    sensitive=sensitive,
                    constraints=tuple(schema_parameter.constraints if schema_parameter is not None else []),
                )
            )
        return targets

    def _body_field_map(self, endpoint: Endpoint) -> dict[str, FieldDefinition]:
        if endpoint.request_body is None:
            return {}
        return {field.name: field for field in endpoint.request_body.fields}

    def _allowed_target(
        self,
        location: ParameterLocation,
        name: str,
        sensitive: bool,
        include_sensitive_fields: bool,
    ) -> bool:
        if sensitive and not include_sensitive_fields:
            return False
        if location == ParameterLocation.HEADER and is_sensitive_key(name):
            return include_sensitive_fields
        return location in {
            ParameterLocation.BODY,
            ParameterLocation.QUERY,
            ParameterLocation.PATH,
            ParameterLocation.HEADER,
        }

    def _infer_field_type(self, value: Any) -> FieldType:
        if isinstance(value, bool):
            return FieldType.BOOLEAN
        if isinstance(value, int):
            return FieldType.INTEGER
        if isinstance(value, float):
            return FieldType.FLOAT
        if isinstance(value, dict):
            return FieldType.OBJECT
        if isinstance(value, list):
            return FieldType.ARRAY
        return FieldType.UNKNOWN


def enum_values(constraints: tuple[Constraint, ...]) -> list[Any]:
    """Return enum values from a target's constraints."""
    for constraint in constraints:
        if constraint.constraint_type == ConstraintType.ENUM and isinstance(constraint.value, list):
            return constraint.value
    return []
