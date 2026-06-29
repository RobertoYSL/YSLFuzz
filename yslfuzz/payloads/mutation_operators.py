"""Type-aware mutation operators."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from yslfuzz.models.enums import AttackCategory, FieldType, ParameterLocation, PayloadKind


@dataclass(frozen=True)
class MutationContext:
    """Schema and runtime context passed to a mutation operator."""

    field_name: str
    field_type: FieldType
    value: Any
    constraints: dict[str, Any]
    nullable: bool = False
    required: bool = False
    nested_fields: dict[str, FieldType] | None = None


@dataclass(frozen=True)
class MutationOperator:
    """A deterministic, safe mutation operator."""

    name: str
    description: str
    supported_field_types: tuple[FieldType, ...]
    supported_locations: tuple[ParameterLocation, ...]
    output_payload_kind: PayloadKind
    safe_label: str
    risk_level: str
    mutate: Callable[[MutationContext], Any]
    attack_category: AttackCategory | None = None

    def applies_to(self, field_type: FieldType, location: ParameterLocation) -> bool:
        return field_type in self.supported_field_types and location in self.supported_locations

    def apply(self, context: MutationContext) -> Any:
        return self.mutate(context)


ALL_LOCATIONS = (
    ParameterLocation.BODY,
    ParameterLocation.QUERY,
    ParameterLocation.PATH,
    ParameterLocation.HEADER,
)


def default_mutation_operators() -> list[MutationOperator]:
    """Return the deterministic MVP mutation operator catalog."""
    return [
        MutationOperator(
            "string_empty",
            "Empty string boundary value.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_empty_string",
            "low",
            lambda _context: "",
        ),
        MutationOperator(
            "string_min_length",
            "Minimum length string boundary value.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_min_length",
            "low",
            lambda context: "m" * max(0, int(context.constraints.get("min_length", 1))),
        ),
        MutationOperator(
            "string_max_length",
            "Maximum length string boundary value.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_max_length",
            "low",
            lambda context: "x" * min(max(1, int(context.constraints.get("max_length", 32))), 256),
        ),
        MutationOperator(
            "string_unicode_marker",
            "Unicode marker string.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_unicode_marker",
            "low",
            lambda _context: "yslfuzz_unicode_probe_å",
        ),
        MutationOperator(
            "string_long_bounded_marker",
            "Long but bounded synthetic string marker.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_bounded_long_string",
            "low",
            lambda _context: "yslfuzz_probe_string_" + ("x" * 96),
        ),
        MutationOperator(
            "string_whitespace",
            "Whitespace-only marker.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_whitespace",
            "low",
            lambda _context: "   ",
        ),
        MutationOperator(
            "string_structured_marker",
            "Harmless structured marker.",
            (FieldType.STRING, FieldType.UNKNOWN),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_structured_marker",
            "low",
            lambda _context: "yslfuzz_probe_string",
        ),
        MutationOperator(
            "numeric_minimum",
            "Minimum numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_numeric_minimum",
            "low",
            lambda context: context.constraints.get("min_value", 0),
        ),
        MutationOperator(
            "numeric_maximum",
            "Maximum numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_numeric_maximum",
            "low",
            lambda context: context.constraints.get("max_value", 100),
        ),
        MutationOperator(
            "numeric_zero",
            "Zero numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_numeric_zero",
            "low",
            lambda context: 0.0 if context.field_type == FieldType.FLOAT else 0,
        ),
        MutationOperator(
            "numeric_negative_one",
            "Negative one numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_numeric_negative_one",
            "low",
            lambda context: -1.0 if context.field_type == FieldType.FLOAT else -1,
        ),
        MutationOperator(
            "numeric_above_maximum",
            "One above maximum numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_numeric_above_maximum",
            "low",
            lambda context: context.constraints.get("max_value", 100) + 1,
        ),
        MutationOperator(
            "numeric_below_minimum",
            "One below minimum numeric value.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_numeric_below_minimum",
            "low",
            lambda context: context.constraints.get("min_value", 0) - 1,
        ),
        MutationOperator(
            "numeric_as_string",
            "Numeric value represented as a string.",
            (FieldType.INTEGER, FieldType.FLOAT),
            ALL_LOCATIONS,
            PayloadKind.INVALID,
            "safe_type_confusion",
            "low",
            lambda context: str(context.value),
        ),
        MutationOperator(
            "boolean_flip",
            "Flip boolean value.",
            (FieldType.BOOLEAN,),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_boolean_flip",
            "low",
            lambda context: not bool(context.value),
        ),
        MutationOperator(
            "boolean_as_string",
            "Boolean value represented as a string.",
            (FieldType.BOOLEAN,),
            ALL_LOCATIONS,
            PayloadKind.INVALID,
            "safe_type_confusion",
            "low",
            lambda context: str(bool(context.value)).lower(),
        ),
        MutationOperator(
            "null_value",
            "Set field to null.",
            tuple(FieldType),
            ALL_LOCATIONS,
            PayloadKind.INVALID,
            "safe_null_mutation",
            "low",
            lambda _context: None,
        ),
        MutationOperator(
            "email_valid_synthetic",
            "Valid synthetic email.",
            (FieldType.EMAIL,),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_email_valid",
            "low",
            lambda _context: "mutated-user@example.test",
        ),
        MutationOperator(
            "email_malformed",
            "Malformed synthetic email.",
            (FieldType.EMAIL,),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_email_malformed",
            "low",
            lambda _context: "yslfuzz-email-probe",
        ),
        MutationOperator(
            "uuid_deterministic",
            "Deterministic synthetic UUID.",
            (FieldType.UUID,),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_uuid_valid",
            "low",
            lambda _context: "00000000-0000-4000-8000-000000000000",
        ),
        MutationOperator(
            "uuid_malformed",
            "Malformed synthetic UUID.",
            (FieldType.UUID,),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_uuid_malformed",
            "low",
            lambda _context: "yslfuzz-uuid-probe",
        ),
        MutationOperator(
            "uri_safe_synthetic",
            "Safe synthetic URI.",
            (FieldType.URI,),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_uri_synthetic",
            "low",
            lambda _context: "https://example.test/yslfuzz-probe",
        ),
        MutationOperator(
            "uri_invalid_reserved",
            "Safe .invalid URI marker.",
            (FieldType.URI,),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_uri_invalid_domain",
            "low",
            lambda _context: "https://yslfuzz-uri-probe.invalid/resource",
        ),
        MutationOperator(
            "object_nested_marker",
            "Mutate one nested object field.",
            (FieldType.OBJECT,),
            (ParameterLocation.BODY,),
            PayloadKind.MUTATED,
            "safe_object_nested_marker",
            "low",
            _object_nested_marker,
        ),
        MutationOperator(
            "array_empty",
            "Empty array boundary value.",
            (FieldType.ARRAY,),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_array_empty",
            "low",
            lambda _context: [],
        ),
        MutationOperator(
            "array_one_item",
            "One-item array value.",
            (FieldType.ARRAY,),
            ALL_LOCATIONS,
            PayloadKind.MUTATED,
            "safe_array_one_item",
            "low",
            lambda _context: ["yslfuzz_array_item"],
        ),
        MutationOperator(
            "array_multi_item",
            "Bounded multi-item array value.",
            (FieldType.ARRAY,),
            ALL_LOCATIONS,
            PayloadKind.BOUNDARY,
            "safe_array_multi_item",
            "low",
            lambda _context: ["yslfuzz_array_item_1", "yslfuzz_array_item_2", "yslfuzz_array_item_3"],
        ),
        MutationOperator(
            "xss_marker_attack",
            "Inert attack-classified marker for shared mutation plumbing.",
            (FieldType.STRING,),
            ALL_LOCATIONS,
            PayloadKind.ATTACK,
            "safe_inert_attack_marker",
            "low",
            lambda _context: "yslfuzz_xss_probe",
            attack_category=AttackCategory.XSS,
        ),
    ]


def _object_nested_marker(context: MutationContext) -> dict[str, Any]:
    original = context.value if isinstance(context.value, dict) else {}
    mutated = dict(original)
    nested_fields = context.nested_fields or {}
    nested_name = sorted(nested_fields)[0] if nested_fields else "yslfuzz_nested"
    mutated[nested_name] = "yslfuzz_probe_string"
    return mutated
