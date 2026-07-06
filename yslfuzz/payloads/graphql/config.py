"""Configuration for safe GraphQL payload generation."""

from pydantic import model_validator

from yslfuzz.models.base import YSLFuzzModel


class GraphQLPayloadConfig(YSLFuzzModel):
    """Safe, bounded options for GraphQL valid payload generation."""

    include_queries: bool = True
    include_mutations: bool = True
    include_subscriptions: bool = False
    max_operations: int | None = None
    max_selection_depth: int = 2
    max_fields_per_selection: int = 5
    max_list_items: int = 1
    include_deprecated_fields: bool = False
    deterministic: bool = True
    random_seed: int | None = None
    operation_name_prefix: str = "YSLFuzz"
    generate_variables: bool = True
    inline_literals: bool = False
    include_typename: bool = False
    max_input_depth: int = 3

    @property
    def seed(self) -> int:
        """Return the effective deterministic seed."""
        return 0 if self.random_seed is None else self.random_seed

    @model_validator(mode="after")
    def validate_bounds(self) -> "GraphQLPayloadConfig":
        """Reject unsafe or ambiguous generation settings."""
        if self.max_operations is not None and self.max_operations < 0:
            raise ValueError("max_operations must be non-negative")
        if self.max_selection_depth < 0:
            raise ValueError("max_selection_depth must be non-negative")
        if self.max_fields_per_selection <= 0:
            raise ValueError("max_fields_per_selection must be greater than 0")
        if self.max_list_items <= 0:
            raise ValueError("max_list_items must be greater than 0")
        if self.max_input_depth < 0:
            raise ValueError("max_input_depth must be non-negative")
        if not self.operation_name_prefix.strip():
            raise ValueError("operation_name_prefix must not be empty")
        return self
