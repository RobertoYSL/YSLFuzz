"""Heuristics for dependency graph inference."""

import re

from yslfuzz.models.enums import FieldType, HttpMethod, ParameterLocation
from yslfuzz.models.schema import Endpoint, FieldDefinition, Parameter


IDENTIFIER_NAMES = {
    "id",
    "uuid",
    "user_id",
    "order_id",
    "product_id",
    "account_id",
}
IDENTIFIER_FIELD_TYPES = {FieldType.UUID, FieldType.STRING, FieldType.INTEGER}


def is_identifier_name(name: str) -> bool:
    """Return true when a field or parameter name looks like an identifier."""
    normalized = normalize_identifier_name(name)
    return normalized in IDENTIFIER_NAMES or normalized.endswith("_id")


def is_identifier_field(field: FieldDefinition) -> bool:
    """Return true when a field likely represents an identifier value."""
    return field.field_type in IDENTIFIER_FIELD_TYPES and is_identifier_name(field.name)


def is_identifier_parameter(parameter: Parameter) -> bool:
    """Return true when a parameter likely consumes an identifier value."""
    return parameter.field_type in IDENTIFIER_FIELD_TYPES and is_identifier_name(parameter.name)


def normalize_identifier_name(name: str) -> str:
    """Normalize an identifier-like name for graph matching."""
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    if normalized == "uuid":
        return "id"
    return normalized


def canonical_identifier_key(name: str, resource_name: str | None = None) -> str:
    """Return a canonical key used to match produced and consumed identifiers."""
    normalized = normalize_identifier_name(name)
    if normalized == "id" and resource_name:
        return f"{singularize_resource(resource_name)}_id"
    return normalized


def resource_name_for_endpoint(endpoint: Endpoint) -> str:
    """Infer a resource name from a REST endpoint path."""
    if not endpoint.path:
        return "resource"
    for part in endpoint.path.strip("/").split("/"):
        if part and not part.startswith("{"):
            return singularize_resource(part)
    return "resource"


def crud_dependency_type(endpoint: Endpoint) -> str | None:
    """Infer a CRUD semantic dependency type for an endpoint."""
    if endpoint.method == HttpMethod.POST and endpoint.path and "{" not in endpoint.path:
        return "CREATES_RESOURCE"
    if endpoint.method == HttpMethod.GET and endpoint.path and "{" in endpoint.path:
        return "READS_RESOURCE"
    if endpoint.method in {HttpMethod.PUT, HttpMethod.PATCH} and endpoint.path and "{" in endpoint.path:
        return "UPDATES_RESOURCE"
    if endpoint.method == HttpMethod.DELETE and endpoint.path and "{" in endpoint.path:
        return "DELETES_RESOURCE"
    return None


def consumer_parameters(endpoint: Endpoint) -> list[Parameter]:
    """Return identifier-like path or query parameters consumed by an endpoint."""
    return [
        parameter
        for parameter in endpoint.parameters
        if parameter.location in {ParameterLocation.PATH, ParameterLocation.QUERY}
        and is_identifier_parameter(parameter)
    ]


def consumer_body_fields(endpoint: Endpoint) -> list[FieldDefinition]:
    """Return identifier-like request body fields consumed by an endpoint."""
    if endpoint.request_body is None:
        return []
    return [
        field
        for field in flatten_fields(endpoint.request_body.fields)
        if is_identifier_field(field)
    ]


def response_identifier_fields(endpoint: Endpoint) -> list[FieldDefinition]:
    """Return identifier-like response fields produced by an endpoint."""
    fields: list[FieldDefinition] = []
    for response in endpoint.responses:
        fields.extend(field for field in flatten_fields(response.fields) if is_identifier_field(field))
    return fields


def flatten_fields(fields: list[FieldDefinition]) -> list[FieldDefinition]:
    """Return fields and nested fields in deterministic traversal order."""
    flattened: list[FieldDefinition] = []
    for field in fields:
        flattened.append(field)
        flattened.extend(flatten_fields(field.nested_fields))
    return flattened


def singularize_resource(resource: str) -> str:
    """Apply a small deterministic singularization heuristic for resource names."""
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", resource).strip("_").lower()
    if normalized.endswith("ies") and len(normalized) > 3:
        return f"{normalized[:-3]}y"
    if normalized.endswith("s") and len(normalized) > 1:
        return normalized[:-1]
    return normalized or "resource"


def stable_key(value: str) -> str:
    """Convert a value into a stable identifier fragment."""
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return normalized or "item"
