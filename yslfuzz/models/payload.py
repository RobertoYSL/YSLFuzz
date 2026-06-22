"""Payload data models."""

from typing import Any

from pydantic import Field, field_serializer, model_validator

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, redact_mapping, redact_value
from yslfuzz.models.enums import AttackCategory, FieldType, ParameterLocation, PayloadKind


class GeneratedParameter(YSLFuzzModel):
    generated_parameter_id: str = Field(default_factory=lambda: prefixed_id("generated_parameter"))
    name: str
    location: ParameterLocation
    value: Any
    field_type: FieldType
    source_field_id: str | None = None
    valid_against_schema: bool = True
    mutation_applied: bool = False
    sensitive: bool = False

    @field_serializer("value")
    def serialize_value(self, value: Any) -> Any:
        if self.sensitive:
            return redact_value(value)
        return value


class Mutation(YSLFuzzModel):
    mutation_id: str = Field(default_factory=lambda: prefixed_id("mutation"))
    name: str
    description: str
    attack_category: AttackCategory | None = None
    target_field_type: FieldType
    target_location: ParameterLocation | None = None
    mutation_operator: str
    safe_label: str


class PayloadCandidate(YSLFuzzModel):
    payload_id: str = Field(default_factory=lambda: prefixed_id("payload"))
    endpoint_id: str
    payload_kind: PayloadKind
    attack_category: AttackCategory | None = None
    content_type: str
    body: dict[str, Any] | str | None = None
    parameters: list[GeneratedParameter] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)
    cookies: dict[str, Any] = Field(default_factory=dict)
    generation_strategy: str
    seed: int
    parent_payload_id: str | None = None

    @model_validator(mode="after")
    def validate_attack_category(self) -> "PayloadCandidate":
        if self.payload_kind == PayloadKind.ATTACK and self.attack_category is None:
            raise ValueError("ATTACK payload requires attack_category")
        return self

    @field_serializer("headers", "cookies")
    def serialize_sensitive_mapping(self, values: dict[str, Any]) -> dict[str, Any]:
        return redact_mapping(values)

    @field_serializer("body")
    def serialize_body(self, value: dict[str, Any] | str | None) -> dict[str, Any] | str | None:
        if isinstance(value, dict):
            return redact_mapping(value)
        return value
