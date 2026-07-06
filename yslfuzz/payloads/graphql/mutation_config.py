"""Configuration for safe GraphQL mutation and attack payload generation."""

from pydantic import Field, model_validator

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import AttackCategory


class GraphQLMutationConfig(YSLFuzzModel):
    """Safe, bounded options for GraphQL non-valid payload generation."""

    include_boundary_payloads: bool = False
    include_invalid_payloads: bool = False
    include_mutated_payloads: bool = False
    include_attack_payloads: bool = False
    enabled_attack_categories: list[AttackCategory] | None = None
    max_mutations_per_payload: int = 10
    max_mutations_per_variable: int = 3
    max_attack_payloads_per_operation: int = 3
    include_sensitive_fields: bool = False
    allow_invalid_enum_values: bool = False
    allow_type_confusion: bool = True
    allow_null_mutations: bool = True
    allow_extra_input_fields: bool = True
    allow_missing_required_fields: bool = True
    allow_introspection_probe: bool = False
    allow_error_leakage_probe: bool = True
    allow_reflection_probe: bool = True
    deterministic: bool = True
    random_seed: int | None = None
    max_input_depth: int = 3
    inert_reflection_marker: str = "yslfuzz_graphql_reflection_marker"
    inert_extra_field_name: str = "yslfuzz_extra_field"
    inert_extra_field_value: str = "yslfuzz_extra_value"
    enabled_payload_kinds: list[str] = Field(default_factory=list, exclude=True)

    @property
    def seed(self) -> int:
        """Return the effective deterministic seed."""
        return 0 if self.random_seed is None else self.random_seed

    @model_validator(mode="after")
    def validate_limits(self) -> "GraphQLMutationConfig":
        """Reject unsafe or unbounded mutation settings."""
        if self.max_mutations_per_payload < 0:
            raise ValueError("max_mutations_per_payload must be non-negative")
        if self.max_mutations_per_variable < 0:
            raise ValueError("max_mutations_per_variable must be non-negative")
        if self.max_attack_payloads_per_operation < 0:
            raise ValueError("max_attack_payloads_per_operation must be non-negative")
        if self.max_input_depth < 0:
            raise ValueError("max_input_depth must be non-negative")
        return self

    def enabled_attack_category_set(self) -> set[AttackCategory]:
        """Return enabled GraphQL attack categories with safe defaults."""
        if self.enabled_attack_categories is None:
            return {
                AttackCategory.INPUT_VALIDATION,
                AttackCategory.INFORMATION_DISCLOSURE,
                AttackCategory.XSS,
                AttackCategory.MASS_ASSIGNMENT,
            }
        return set(self.enabled_attack_categories)
