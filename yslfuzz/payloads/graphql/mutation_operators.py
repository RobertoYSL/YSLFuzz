"""Safe GraphQL variable mutation operators."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from yslfuzz.discovery.graphql.models import GraphQLEnum, GraphQLSchema, GraphQLTypeKind, GraphQLTypeRef
from yslfuzz.models.base import is_sensitive_key, prefixed_id
from yslfuzz.models.enums import PayloadKind
from yslfuzz.models.payload import PayloadCandidate


BOUNDARY_STRING_MARKER = "yslfuzz_graphql_boundary_string"
UNICODE_MARKER = "yslfuzz_unicode_\u2603"
LONG_BOUNDARY_STRING = "yslfuzz_" + ("x" * 128)
INVALID_ENUM_MARKER = "YSLFUZZ_INVALID_ENUM"
INVALID_TYPE_MARKER = {"yslfuzz_invalid_type": True}


@dataclass(frozen=True)
class GraphQLMutationContext:
    """Context needed to mutate a GraphQL variable."""

    variable_name: str
    type_ref: GraphQLTypeRef
    original_value: Any
    target_path: tuple[str, ...]
    schema: GraphQLSchema

    @property
    def target_path_text(self) -> str:
        """Return a stable dotted path for metadata."""
        return ".".join(self.target_path)


@dataclass(frozen=True)
class GraphQLMutation:
    """A single safe GraphQL variable mutation."""

    operator: str
    payload_kind: PayloadKind
    value: Any
    mutated_type: str
    safety_label: str
    risk_level: str = "low"
    inert_marker: str | None = None


class GraphQLMutationOperator:
    """Apply a prepared mutation to a GraphQL payload candidate."""

    def apply(
        self,
        payload: PayloadCandidate,
        context: GraphQLMutationContext,
        mutation: GraphQLMutation,
    ) -> PayloadCandidate:
        """Return a mutated copy of a GraphQL payload."""
        if not isinstance(payload.body, dict):
            raise ValueError("GraphQL payload body must be a mapping")
        body = deepcopy(payload.body)
        variables = deepcopy(body.get("variables", {}))
        if not isinstance(variables, dict):
            variables = {}
        _set_path(variables, context.target_path, mutation.value)
        body["variables"] = variables
        return payload.model_copy(
            deep=True,
            update={
                "payload_id": prefixed_id("payload"),
                "payload_kind": mutation.payload_kind,
                "body": body,
                "parent_payload_id": payload.payload_id,
                "generation_strategy": "graphql_variable_mutation_mvp",
                "metadata": {
                    **payload.metadata,
                    "api_style": "GRAPHQL",
                    "graphql_mutation_operator": mutation.operator,
                    "graphql_target_variable": context.variable_name,
                    "graphql_target_path": context.target_path_text,
                    "graphql_original_type": context.type_ref.display(),
                    "graphql_mutated_type": mutation.mutated_type,
                    "safety_label": mutation.safety_label,
                    "risk_level": mutation.risk_level,
                    "inert_marker": mutation.inert_marker,
                    "redaction_applied": True,
                },
            },
        )


def boundary_mutations(context: GraphQLMutationContext, allow_type_confusion: bool) -> list[GraphQLMutation]:
    """Return bounded BOUNDARY mutations for a GraphQL variable."""
    unwrapped = unwrap_non_null(context.type_ref)
    if unwrapped.kind == GraphQLTypeKind.LIST:
        original_item = _first_item(context.original_value)
        return [
            _mutation("list_empty_boundary", PayloadKind.BOUNDARY, [], "list"),
            _mutation("list_one_item_boundary", PayloadKind.BOUNDARY, [original_item], "list"),
            _mutation("list_multi_item_boundary", PayloadKind.BOUNDARY, [original_item, original_item], "list"),
        ]
    enum = enum_for_ref(unwrapped, context.schema)
    if enum is not None:
        alternate = alternate_enum_value(enum, context.original_value)
        return [_mutation("enum_alternate_boundary", PayloadKind.BOUNDARY, alternate, "enum")] if alternate else []
    name = unwrapped.named_type()
    if name == "ID":
        return [
            _mutation("id_empty_boundary", PayloadKind.BOUNDARY, "", "ID"),
            _mutation("id_marker_boundary", PayloadKind.BOUNDARY, "yslfuzz-id-boundary", "ID"),
            _mutation("id_numeric_boundary", PayloadKind.BOUNDARY, "1", "ID"),
        ]
    if name == "String" or name is None:
        return [
            _mutation("string_empty_boundary", PayloadKind.BOUNDARY, "", "String"),
            _mutation("string_whitespace_boundary", PayloadKind.BOUNDARY, "   ", "String"),
            _mutation("string_unicode_boundary", PayloadKind.BOUNDARY, UNICODE_MARKER, "String"),
            _mutation("string_long_boundary", PayloadKind.BOUNDARY, LONG_BOUNDARY_STRING, "String"),
            _mutation("string_marker_boundary", PayloadKind.BOUNDARY, BOUNDARY_STRING_MARKER, "String"),
        ]
    if name == "Int":
        values: list[Any] = [0, -1, 1]
        if allow_type_confusion:
            values.append("1")
        return [_mutation(f"int_boundary_{index}", PayloadKind.BOUNDARY, value, type(value).__name__) for index, value in enumerate(values)]
    if name == "Float":
        values = [0.0, -1.0, 1.0]
        if allow_type_confusion:
            values.append("1.0")
        return [_mutation(f"float_boundary_{index}", PayloadKind.BOUNDARY, value, type(value).__name__) for index, value in enumerate(values)]
    if name == "Boolean":
        values = [not bool(context.original_value)]
        if allow_type_confusion:
            values.append("true")
        return [_mutation(f"boolean_boundary_{index}", PayloadKind.BOUNDARY, value, type(value).__name__) for index, value in enumerate(values)]
    return []


def invalid_mutations(
    context: GraphQLMutationContext,
    *,
    allow_null_mutations: bool,
    allow_type_confusion: bool,
    allow_invalid_enum_values: bool,
) -> list[GraphQLMutation]:
    """Return safe INVALID mutations for a GraphQL variable."""
    mutations: list[GraphQLMutation] = []
    if allow_null_mutations and is_non_null(context.type_ref):
        mutations.append(_mutation("null_for_non_null", PayloadKind.INVALID, None, "null", "schema_invalid"))
    unwrapped = unwrap_non_null(context.type_ref)
    enum = enum_for_ref(unwrapped, context.schema)
    if enum is not None:
        if allow_invalid_enum_values:
            mutations.append(
                _mutation(
                    "invalid_enum_value",
                    PayloadKind.INVALID,
                    INVALID_ENUM_MARKER,
                    "enum",
                    "schema_invalid",
                )
            )
        return mutations
    if unwrapped.kind == GraphQLTypeKind.LIST:
        mutations.append(_mutation("list_item_wrong_type", PayloadKind.INVALID, [INVALID_TYPE_MARKER], "list<object>", "schema_invalid"))
        mutations.append(_mutation("scalar_instead_of_list", PayloadKind.INVALID, "yslfuzz_scalar_instead_of_list", "String", "schema_invalid"))
    elif allow_type_confusion:
        name = unwrapped.named_type()
        if name in {"String", "ID", "Int", "Float", "Boolean"}:
            mutations.append(_mutation("object_instead_of_scalar", PayloadKind.INVALID, INVALID_TYPE_MARKER, "object", "schema_invalid"))
            mutations.append(_mutation("wrong_scalar_type", PayloadKind.INVALID, _wrong_scalar_value(name), "wrong_scalar", "schema_invalid"))
        else:
            mutations.append(_mutation("scalar_instead_of_object", PayloadKind.INVALID, "yslfuzz_scalar_instead_of_object", "String", "schema_invalid"))
    return mutations


def mutated_mutations(context: GraphQLMutationContext, allow_type_confusion: bool) -> list[GraphQLMutation]:
    """Return safe MUTATED semantic variations for a GraphQL variable."""
    unwrapped = unwrap_non_null(context.type_ref)
    enum = enum_for_ref(unwrapped, context.schema)
    if enum is not None:
        alternate = alternate_enum_value(enum, context.original_value)
        return [_mutation("enum_valid_alternate", PayloadKind.MUTATED, alternate, "enum", "semantic_variation")] if alternate else []
    name = unwrapped.named_type()
    if name == "String":
        return [_mutation("string_alternate_value", PayloadKind.MUTATED, "yslfuzz-string-alt", "String", "semantic_variation")]
    if name == "ID":
        return [_mutation("id_alternate_value", PayloadKind.MUTATED, "yslfuzz-id-002", "ID", "semantic_variation")]
    if name == "Int":
        return [_mutation("int_alternate_value", PayloadKind.MUTATED, 2, "Int", "semantic_variation")]
    if name == "Float":
        return [_mutation("float_alternate_value", PayloadKind.MUTATED, 2.0, "Float", "semantic_variation")]
    if name == "Boolean":
        return [_mutation("boolean_alternate_value", PayloadKind.MUTATED, not bool(context.original_value), "Boolean", "semantic_variation")]
    if unwrapped.kind == GraphQLTypeKind.LIST:
        item = _first_item(context.original_value)
        return [_mutation("list_alternate_size", PayloadKind.MUTATED, [item], "list", "semantic_variation")]
    del allow_type_confusion
    return []


def is_sensitive_variable(name: str, metadata: dict[str, Any] | None = None) -> bool:
    """Return true when a GraphQL variable should be treated as sensitive."""
    if is_sensitive_key(name):
        return True
    if metadata is None:
        return False
    return bool(metadata.get("sensitive"))


def unwrap_non_null(type_ref: GraphQLTypeRef) -> GraphQLTypeRef:
    """Remove GraphQL NON_NULL wrappers."""
    current = type_ref
    while current.kind == GraphQLTypeKind.NON_NULL and current.of_type is not None:
        current = current.of_type
    return current


def is_non_null(type_ref: GraphQLTypeRef) -> bool:
    """Return true when a type reference is non-null at the current level."""
    return type_ref.kind == GraphQLTypeKind.NON_NULL


def enum_for_ref(type_ref: GraphQLTypeRef, schema: GraphQLSchema) -> GraphQLEnum | None:
    """Return enum metadata for a type reference, if any."""
    name = type_ref.named_type()
    if name is None:
        return None
    return next((enum for enum in schema.enums if enum.name == name), None)


def alternate_enum_value(enum: GraphQLEnum, current_value: Any) -> str | None:
    """Return a deterministic alternate enum value."""
    for value in enum.enum_values:
        if value != current_value:
            return value
    return None


def _mutation(
    operator: str,
    kind: PayloadKind,
    value: Any,
    mutated_type: str,
    safety_label: str = "safe_boundary",
) -> GraphQLMutation:
    return GraphQLMutation(
        operator=operator,
        payload_kind=kind,
        value=value,
        mutated_type=mutated_type,
        safety_label=safety_label,
    )


def _set_path(values: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current: dict[str, Any] = values
    for segment in path[:-1]:
        child = current.get(segment)
        if not isinstance(child, dict):
            child = {}
            current[segment] = child
        current = child
    current[path[-1]] = value


def _first_item(value: Any) -> Any:
    if isinstance(value, list) and value:
        return deepcopy(value[0])
    return "yslfuzz-list-item"


def _wrong_scalar_value(type_name: str | None) -> Any:
    if type_name in {"String", "ID"}:
        return 1
    if type_name in {"Int", "Float"}:
        return "yslfuzz_wrong_scalar"
    if type_name == "Boolean":
        return "not-a-boolean"
    return INVALID_TYPE_MARKER
