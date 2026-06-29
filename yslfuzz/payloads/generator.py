"""Valid payload generation for REST endpoints."""

from collections.abc import Mapping
from typing import Any

from yslfuzz.models.enums import ApiStyle, ParameterLocation, PayloadKind
from yslfuzz.models.payload import GeneratedParameter, PayloadCandidate
from yslfuzz.models.schema import Endpoint, FieldDefinition, Parameter
from yslfuzz.payloads.value_factory import ValueFactory


class PayloadGenerator:
    """Generate one schema-valid baseline payload for an endpoint."""

    def __init__(
        self,
        seed: int | None = None,
        provided_parameters: Mapping[str, Any] | None = None,
    ) -> None:
        self.seed = 0 if seed is None else seed
        self._provided_parameters = dict(provided_parameters or {})
        self._value_factory = ValueFactory(seed=self.seed)

    def generate_for_endpoint(self, endpoint: Endpoint) -> PayloadCandidate:
        """Generate a valid payload candidate for a REST endpoint."""
        if endpoint.api_style != ApiStyle.REST:
            raise ValueError("PayloadGenerator MVP supports REST endpoints only")

        generated_parameters = self._generate_parameters(endpoint.parameters)
        headers = {
            parameter.name: parameter.value
            for parameter in generated_parameters
            if parameter.location == ParameterLocation.HEADER
        }

        return PayloadCandidate(
            endpoint_id=endpoint.endpoint_id,
            payload_kind=PayloadKind.VALID,
            content_type=self._content_type(endpoint),
            body=self._generate_body(endpoint),
            parameters=generated_parameters,
            headers=headers,
            generation_strategy="valid_schema_mvp",
            seed=self.seed,
        )

    def _generate_body(self, endpoint: Endpoint) -> dict[str, Any] | None:
        if endpoint.request_body is None:
            return None
        if endpoint.request_body.content_type != "application/json":
            return None

        return {
            field.name: self._value_factory.generate_for_field(field)
            for field in endpoint.request_body.fields
            if self._should_include_body_field(field)
        }

    def _generate_parameters(self, parameters: list[Parameter]) -> list[GeneratedParameter]:
        generated: list[GeneratedParameter] = []
        for parameter in parameters:
            if parameter.sensitive and parameter.name not in self._provided_parameters:
                continue
            value = self._provided_parameters.get(
                parameter.name,
                self._value_factory.generate_for_parameter(parameter),
            )
            generated.append(
                GeneratedParameter(
                    name=parameter.name,
                    location=parameter.location,
                    value=value,
                    field_type=parameter.field_type,
                    source_field_id=parameter.parameter_id,
                    valid_against_schema=True,
                    sensitive=parameter.sensitive,
                )
            )
        return generated

    def _should_include_body_field(self, field: FieldDefinition) -> bool:
        if field.read_only:
            return False
        if field.required:
            return True
        return True

    def _content_type(self, endpoint: Endpoint) -> str:
        if endpoint.request_body is None:
            return "application/json"
        return endpoint.request_body.content_type
