"""Schema-domain models for normalized API structure."""

from datetime import datetime
from typing import Any

from pydantic import Field, field_serializer, model_validator

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, redact_value, utc_now
from yslfuzz.models.enums import (
    ApiStyle,
    ConstraintType,
    FieldType,
    HttpMethod,
    ParameterLocation,
)


class TypeReference(YSLFuzzModel):
    type_id: str | None = None
    name: str | None = None
    field_type: FieldType = FieldType.UNKNOWN


class ExampleValue(YSLFuzzModel):
    name: str | None = None
    value: Any
    summary: str | None = None
    description: str | None = None
    sensitive: bool = False

    @field_serializer("value")
    def serialize_value(self, value: Any) -> Any:
        if self.sensitive:
            return redact_value(value)
        return value


class SchemaSource(YSLFuzzModel):
    source_id: str = Field(default_factory=lambda: prefixed_id("source"))
    source_type: str
    location: str
    api_style: ApiStyle
    raw_content_hash: str | None = None
    imported_at: datetime = Field(default_factory=utc_now)
    parser_version: str = "0.1.0"


class Constraint(YSLFuzzModel):
    constraint_id: str = Field(default_factory=lambda: prefixed_id("constraint"))
    constraint_type: ConstraintType
    value: Any
    source: str
    description: str | None = None


class FieldDefinition(YSLFuzzModel):
    field_id: str = Field(default_factory=lambda: prefixed_id("field"))
    name: str
    field_type: FieldType
    required: bool = False
    nullable: bool = False
    read_only: bool = False
    write_only: bool = False
    sensitive: bool = False
    constraints: list[Constraint] = Field(default_factory=list)
    nested_fields: list["FieldDefinition"] = Field(default_factory=list)
    array_item_type: TypeReference | None = None
    description: str | None = None
    example_value: Any | None = None

    @field_serializer("example_value")
    def serialize_example_value(self, value: Any | None) -> Any | None:
        if self.sensitive:
            return redact_value(value)
        return value


class TypeDefinition(YSLFuzzModel):
    type_id: str = Field(default_factory=lambda: prefixed_id("type"))
    name: str
    api_style: ApiStyle
    field_type: FieldType
    fields: list[FieldDefinition] = Field(default_factory=list)
    enum_values: list[str] | None = None
    description: str | None = None


class Parameter(YSLFuzzModel):
    parameter_id: str = Field(default_factory=lambda: prefixed_id("parameter"))
    name: str
    location: ParameterLocation
    field_type: FieldType
    required: bool = False
    constraints: list[Constraint] = Field(default_factory=list)
    default_value: Any | None = None
    example_value: Any | None = None
    description: str | None = None
    sensitive: bool = False

    @field_serializer("default_value", "example_value")
    def serialize_sensitive_value(self, value: Any | None) -> Any | None:
        if self.sensitive:
            return redact_value(value)
        return value


class RequestBodyDefinition(YSLFuzzModel):
    request_body_id: str = Field(default_factory=lambda: prefixed_id("request_body"))
    content_type: str
    required: bool = False
    root_type: TypeReference | None = None
    fields: list[FieldDefinition] = Field(default_factory=list)
    examples: list[ExampleValue] = Field(default_factory=list)


class ResponseDefinition(YSLFuzzModel):
    response_definition_id: str = Field(default_factory=lambda: prefixed_id("response_def"))
    status_code: int | str
    description: str | None = None
    content_type: str | None = None
    body_type: TypeReference | None = None
    fields: list[FieldDefinition] = Field(default_factory=list)


class Endpoint(YSLFuzzModel):
    endpoint_id: str = Field(default_factory=lambda: prefixed_id("endpoint"))
    api_schema_id: str
    name: str
    api_style: ApiStyle
    path: str | None = None
    method: HttpMethod | None = None
    graphql_operation_type: str | None = None
    graphql_operation_name: str | None = None
    summary: str | None = None
    description: str | None = None
    auth_required: bool = False
    deprecated: bool = False
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: RequestBodyDefinition | None = None
    responses: list[ResponseDefinition] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_endpoint_shape(self) -> "Endpoint":
        if self.api_style == ApiStyle.REST and (self.method is None or not self.path):
            raise ValueError("REST endpoint requires method and path")
        if self.api_style == ApiStyle.GRAPHQL and (
            not self.graphql_operation_type or not self.graphql_operation_name
        ):
            raise ValueError(
                "GraphQL operation requires graphql_operation_type and graphql_operation_name"
            )
        return self


class ApiSchema(YSLFuzzModel):
    api_schema_id: str = Field(default_factory=lambda: prefixed_id("api_schema"))
    target_id: str
    title: str | None = None
    version: str | None = None
    api_style: ApiStyle
    base_url: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    types: list[TypeDefinition] = Field(default_factory=list)
    auth_schemes: list["AuthScheme"] = Field(default_factory=list)
    created_from: list[SchemaSource] = Field(default_factory=list)


from yslfuzz.models.auth import AuthScheme  # noqa: E402

ApiSchema.model_rebuild()
