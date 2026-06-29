"""Runtime variable binding for payload candidates."""

from typing import Any

from yslfuzz.models.enums import FieldType, ParameterLocation
from yslfuzz.models.payload import GeneratedParameter, PayloadCandidate
from yslfuzz.models.dependency import VariableBinding


class BindingResolutionError(ValueError):
    """Raised when a required binding cannot be resolved."""


class BindingResolver:
    """Apply known runtime values to generated payloads."""

    def apply(
        self,
        payload: PayloadCandidate,
        bindings: list[VariableBinding],
        known_values: dict[str, Any],
        required: bool = True,
    ) -> PayloadCandidate:
        """Return a payload copy with bindings applied over generated values."""
        updated_payload = payload.model_copy(deep=True)
        for binding in bindings:
            value = self._lookup(binding.source, known_values)
            if value is None:
                if required:
                    raise BindingResolutionError(
                        f"Missing required binding source '{binding.source}' for target '{binding.target}'"
                    )
                continue
            self._apply_binding(updated_payload, binding.target, value)
        return updated_payload

    def _lookup(self, source: str, known_values: dict[str, Any]) -> Any | None:
        if source in known_values:
            return known_values[source]
        if source.endswith("_id") and "id" in known_values:
            return known_values["id"]
        if source == "id":
            identifier_values = [
                value for key, value in known_values.items() if key.endswith("_id")
            ]
            if len(identifier_values) == 1:
                return identifier_values[0]
        return None

    def _apply_binding(self, payload: PayloadCandidate, target: str, value: Any) -> None:
        location, name = self._target_parts(target)
        if location == ParameterLocation.BODY:
            self._apply_body_binding(payload, name, value)
            return
        self._apply_parameter_binding(payload, location, name, value)

    def _target_parts(self, target: str) -> tuple[ParameterLocation, str]:
        if "." not in target:
            return ParameterLocation.PATH, target
        raw_location, name = target.split(".", 1)
        location = {
            "path": ParameterLocation.PATH,
            "query": ParameterLocation.QUERY,
            "header": ParameterLocation.HEADER,
            "body": ParameterLocation.BODY,
        }.get(raw_location.lower())
        if location is None:
            raise BindingResolutionError(f"Unsupported binding target location '{raw_location}'")
        return location, name

    def _apply_parameter_binding(
        self,
        payload: PayloadCandidate,
        location: ParameterLocation,
        name: str,
        value: Any,
    ) -> None:
        for parameter in payload.parameters:
            if parameter.location == location and parameter.name == name:
                parameter.value = value
                return
        payload.parameters.append(
            GeneratedParameter(
                name=name,
                location=location,
                value=value,
                field_type=self._field_type_for_value(value),
                source_field_id=None,
                valid_against_schema=True,
            )
        )

    def _apply_body_binding(self, payload: PayloadCandidate, name: str, value: Any) -> None:
        if not isinstance(payload.body, dict):
            payload.body = {}
        payload.body[name] = value

    def _field_type_for_value(self, value: Any) -> FieldType:
        if isinstance(value, bool):
            return FieldType.BOOLEAN
        if isinstance(value, int):
            return FieldType.INTEGER
        if isinstance(value, float):
            return FieldType.FLOAT
        return FieldType.STRING
