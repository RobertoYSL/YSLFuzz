"""Mutation engine configuration."""

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import AttackCategory, PayloadKind


class MutationConfig(YSLFuzzModel):
    """Safe defaults for deterministic payload mutation."""

    enabled_payload_kinds: list[PayloadKind] = Field(
        default_factory=lambda: [PayloadKind.BOUNDARY, PayloadKind.INVALID, PayloadKind.MUTATED]
    )
    enabled_attack_categories: list[AttackCategory] = Field(default_factory=list)
    max_mutations_per_payload: int = 50
    max_mutations_per_field: int = 4
    include_sensitive_fields: bool = False
    deterministic: bool = True
    random_seed: int | None = None
    allow_invalid_enum_values: bool = False
    allow_type_confusion: bool = True
    allow_boundary_values: bool = True
    allow_null_mutations: bool = True
