"""Controlled attack payload generation."""

from collections.abc import Sequence
from random import Random
from typing import Any

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import AttackCategory, FieldType, ParameterLocation, PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Endpoint
from yslfuzz.payloads.attack_templates import AttackTemplate, default_attack_templates
from yslfuzz.payloads.targeting import AttackTarget, AttackTargetSelector, enum_values


MVP_ATTACK_CATEGORIES = [
    AttackCategory.SQL_INJECTION,
    AttackCategory.NOSQL_INJECTION,
    AttackCategory.COMMAND_INJECTION,
    AttackCategory.SSRF,
    AttackCategory.XSS,
    AttackCategory.MASS_ASSIGNMENT,
    AttackCategory.BROKEN_ACCESS_CONTROL,
    AttackCategory.INPUT_VALIDATION,
    AttackCategory.INFORMATION_DISCLOSURE,
]


class AttackGenerationConfig(YSLFuzzModel):
    """Configuration for controlled attack payload generation."""

    enabled_categories: list[AttackCategory] = Field(default_factory=lambda: list(MVP_ATTACK_CATEGORIES))
    max_payloads_per_endpoint: int = 20
    max_payloads_per_field: int = 2
    include_sensitive_fields: bool = False
    seed: int = 0


class AttackPayloadGenerator:
    """Generate controlled, non-executing attack payload candidates."""

    def __init__(
        self,
        config: AttackGenerationConfig | None = None,
        templates: Sequence[AttackTemplate] | None = None,
        target_selector: AttackTargetSelector | None = None,
    ) -> None:
        self.config = config or AttackGenerationConfig()
        self._templates = list(templates or default_attack_templates())
        self._target_selector = target_selector or AttackTargetSelector()
        self._random = Random(self.config.seed)

    def generate(self, endpoint: Endpoint, valid_payload: PayloadCandidate) -> list[PayloadCandidate]:
        """Generate attack payloads for an endpoint from a valid baseline payload."""
        targets = self._target_selector.select(
            endpoint,
            valid_payload,
            include_sensitive_fields=self.config.include_sensitive_fields,
        )
        target_template_pairs = [
            (target, template)
            for target in targets
            for template in self._matching_templates(target)
        ]
        self._random.shuffle(target_template_pairs)

        results: list[PayloadCandidate] = []
        per_field_counts: dict[str, int] = {}
        for target, template in target_template_pairs:
            if len(results) >= self.config.max_payloads_per_endpoint:
                break
            count_key = target.target_path
            if per_field_counts.get(count_key, 0) >= self.config.max_payloads_per_field:
                continue
            results.append(self._attack_payload(valid_payload, target, template))
            per_field_counts[count_key] = per_field_counts.get(count_key, 0) + 1
        return results

    def generate_many(
        self,
        endpoint: Endpoint,
        valid_payloads: Sequence[PayloadCandidate],
    ) -> list[PayloadCandidate]:
        """Generate attack payloads from multiple valid payload candidates."""
        results: list[PayloadCandidate] = []
        for payload in valid_payloads:
            if len(results) >= self.config.max_payloads_per_endpoint:
                break
            remaining = self.config.max_payloads_per_endpoint - len(results)
            child_config = self.config.model_copy(update={"max_payloads_per_endpoint": remaining})
            child = AttackPayloadGenerator(
                config=child_config,
                templates=self._templates,
                target_selector=self._target_selector,
            )
            results.extend(child.generate(endpoint, payload))
        return results

    def _matching_templates(self, target: AttackTarget) -> list[AttackTemplate]:
        templates: list[AttackTemplate] = []
        for template in self._templates:
            if template.attack_category not in self.config.enabled_categories:
                continue
            if target.location not in template.allowed_locations:
                continue
            if target.field_type == FieldType.ENUM and not (
                template.attack_category == AttackCategory.INPUT_VALIDATION
                and template.input_validation_only_for_enum
            ):
                continue
            if target.field_type in template.target_field_types:
                templates.append(template)
        return templates

    def _attack_payload(
        self,
        valid_payload: PayloadCandidate,
        target: AttackTarget,
        template: AttackTemplate,
    ) -> PayloadCandidate:
        payload = valid_payload.model_copy(
            deep=True,
            update={
                "payload_id": self._payload_id(valid_payload, target, template),
                "payload_kind": PayloadKind.ATTACK,
                "attack_category": template.attack_category,
                "parent_payload_id": valid_payload.payload_id,
                "generation_strategy": (
                    f"attack_{template.attack_category.value.lower()}_{template.name}"
                ),
                "seed": self.config.seed,
            },
        )
        payload.metadata.update(
            {
                "target_field": target.name,
                "target_location": target.location.value,
                "target_field_type": target.field_type.value,
                "target_sensitive": target.sensitive,
                "mutation_name": template.name,
                "safety_label": template.safety_label,
                "description": template.description,
                "non_executing": True,
            }
        )
        self._apply_probe(payload, target, self._probe_value(target, template))
        return payload

    def _apply_probe(self, payload: PayloadCandidate, target: AttackTarget, probe_value: Any) -> None:
        if target.location == ParameterLocation.BODY:
            if isinstance(payload.body, dict):
                if target.field_type == FieldType.OBJECT and isinstance(probe_value, dict):
                    original = payload.body.get(target.name)
                    if isinstance(original, dict):
                        payload.body[target.name] = {**original, **probe_value}
                    else:
                        payload.body[target.name] = probe_value
                elif target.field_type == FieldType.ARRAY:
                    payload.body[target.name] = [probe_value]
                else:
                    payload.body[target.name] = probe_value
            return

        for parameter in payload.parameters:
            if parameter.location == target.location and parameter.name == target.name:
                parameter.value = probe_value
                parameter.mutation_applied = True
                parameter.sensitive = target.sensitive
                return

    def _probe_value(self, target: AttackTarget, template: AttackTemplate) -> Any:
        if target.field_type == FieldType.BOOLEAN and template.probe_value is None:
            return not bool(target.value)
        if target.field_type == FieldType.ENUM and template.attack_category != AttackCategory.INPUT_VALIDATION:
            values = enum_values(target.constraints)
            if values:
                return values[0]
        if target.field_type == FieldType.UUID and template.attack_category == AttackCategory.INPUT_VALIDATION:
            return "00000000-0000-4000-8000-000000000000"
        if target.field_type == FieldType.EMAIL and template.attack_category == AttackCategory.INPUT_VALIDATION:
            return "yslfuzz_input_validation_probe"
        if target.field_type == FieldType.ARRAY and not isinstance(template.probe_value, list):
            return template.probe_value
        return template.probe_value

    def _payload_id(
        self,
        valid_payload: PayloadCandidate,
        target: AttackTarget,
        template: AttackTemplate,
    ) -> str:
        safe_target = target.target_path.replace(".", "_").replace("-", "_").lower()
        return f"payload_attack_{valid_payload.payload_id}_{template.name}_{safe_target}"
