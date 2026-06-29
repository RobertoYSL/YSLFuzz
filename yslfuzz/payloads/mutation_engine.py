"""Generic type-aware payload mutation engine."""

from dataclasses import dataclass
from collections.abc import Callable
from random import Random
from typing import Any

from yslfuzz.models.base import is_sensitive_key
from yslfuzz.models.enums import ConstraintType, FieldType, ParameterLocation, PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Constraint, Endpoint, FieldDefinition
from yslfuzz.payloads.mutation_config import MutationConfig
from yslfuzz.payloads.mutation_operators import (
    MutationContext,
    MutationOperator,
    default_mutation_operators,
)


@dataclass(frozen=True)
class MutationTarget:
    """A body field or generated parameter eligible for mutation."""

    name: str
    location: ParameterLocation
    field_type: FieldType
    value: Any
    constraints: tuple[Constraint, ...] = ()
    nullable: bool = False
    required: bool = False
    sensitive: bool = False
    nested_fields: tuple[FieldDefinition, ...] = ()

    @property
    def target_path(self) -> str:
        return f"{self.location.value.lower()}.{self.name}"


class MutationEngine:
    """Generate deterministic, type-aware mutated payload candidates."""

    def __init__(
        self,
        config: MutationConfig | None = None,
        operators: list[MutationOperator] | None = None,
    ) -> None:
        self.config = config or MutationConfig()
        self.operators = list(operators or default_mutation_operators())
        self._random = Random(self.config.random_seed or 0)

    def mutate(self, endpoint: Endpoint, payload: PayloadCandidate) -> list[PayloadCandidate]:
        """Return mutated payload variants for an endpoint and source payload."""
        candidates: list[tuple[MutationTarget, MutationOperator, Any]] = []
        for target in self._targets(endpoint, payload):
            for operator in self._operators_for(target):
                value = operator.apply(self._context(target))
                candidates.append((target, operator, value))
            candidates.extend(self._enum_candidates(target))

        if self.config.deterministic:
            self._random.shuffle(candidates)

        results: list[PayloadCandidate] = []
        per_field_counts: dict[str, int] = {}
        for target, operator, value in candidates:
            if len(results) >= self.config.max_mutations_per_payload:
                break
            if per_field_counts.get(target.target_path, 0) >= self.config.max_mutations_per_field:
                continue
            mutated = self._mutated_payload(payload, target, operator, value)
            if mutated.payload_kind not in self.config.enabled_payload_kinds:
                continue
            if (
                mutated.payload_kind == PayloadKind.ATTACK
                and mutated.attack_category not in self.config.enabled_attack_categories
            ):
                continue
            results.append(mutated)
            per_field_counts[target.target_path] = per_field_counts.get(target.target_path, 0) + 1
        return results

    def _targets(self, endpoint: Endpoint, payload: PayloadCandidate) -> list[MutationTarget]:
        targets: list[MutationTarget] = []
        field_map = self._body_field_map(endpoint)
        if isinstance(payload.body, dict):
            for name in sorted(payload.body):
                field = field_map.get(name)
                sensitive = (field.sensitive if field is not None else False) or is_sensitive_key(name)
                if sensitive and not self.config.include_sensitive_fields:
                    continue
                targets.append(
                    MutationTarget(
                        name=name,
                        location=ParameterLocation.BODY,
                        field_type=field.field_type if field is not None else self._infer_field_type(payload.body[name]),
                        value=payload.body[name],
                        constraints=tuple(field.constraints if field is not None else []),
                        nullable=field.nullable if field is not None else payload.body[name] is None,
                        required=field.required if field is not None else False,
                        sensitive=sensitive,
                        nested_fields=tuple(field.nested_fields if field is not None else []),
                    )
                )

        parameter_schema = {parameter.name: parameter for parameter in endpoint.parameters}
        for parameter in sorted(payload.parameters, key=lambda item: (item.location.value, item.name)):
            schema_parameter = parameter_schema.get(parameter.name)
            sensitive = parameter.sensitive or (schema_parameter.sensitive if schema_parameter else False)
            if (sensitive or self._auth_header(parameter.location, parameter.name)) and not self.config.include_sensitive_fields:
                continue
            targets.append(
                MutationTarget(
                    name=parameter.name,
                    location=parameter.location,
                    field_type=parameter.field_type,
                    value=parameter.value,
                    constraints=tuple(schema_parameter.constraints if schema_parameter is not None else []),
                    required=schema_parameter.required if schema_parameter is not None else False,
                    sensitive=sensitive or self._auth_header(parameter.location, parameter.name),
                )
            )
        return targets

    def _operators_for(self, target: MutationTarget) -> list[MutationOperator]:
        selected: list[MutationOperator] = []
        for operator in self.operators:
            if not operator.applies_to(target.field_type, target.location):
                continue
            if operator.output_payload_kind not in self.config.enabled_payload_kinds:
                continue
            if operator.output_payload_kind == PayloadKind.BOUNDARY and not self.config.allow_boundary_values:
                continue
            if operator.name.endswith("as_string") and not self.config.allow_type_confusion:
                continue
            if operator.name == "null_value" and not self._allow_null_operator(target):
                continue
            if operator.name.startswith("numeric_above") or operator.name.startswith("numeric_below"):
                if not self.config.allow_boundary_values:
                    continue
            if operator.output_payload_kind == PayloadKind.ATTACK and (
                operator.attack_category not in self.config.enabled_attack_categories
            ):
                continue
            if target.field_type == FieldType.ENUM:
                continue
            selected.append(operator)
        return selected

    def _enum_candidates(
        self,
        target: MutationTarget,
    ) -> list[tuple[MutationTarget, MutationOperator, Any]]:
        if target.field_type != FieldType.ENUM:
            return []
        values = self._enum_values(target.constraints)
        candidates: list[tuple[MutationTarget, MutationOperator, Any]] = []
        for value in values:
            operator = MutationOperator(
                name=f"enum_allowed_{value}",
                description="Allowed enum value mutation.",
                supported_field_types=(FieldType.ENUM,),
                supported_locations=(target.location,),
                output_payload_kind=PayloadKind.MUTATED,
                safe_label="safe_enum_allowed",
                risk_level="low",
                mutate=self._constant_mutator(value),
            )
            if operator.output_payload_kind in self.config.enabled_payload_kinds:
                candidates.append((target, operator, value))
        if self.config.allow_invalid_enum_values and PayloadKind.INVALID in self.config.enabled_payload_kinds:
            operator = MutationOperator(
                name="enum_invalid_marker",
                description="Invalid synthetic enum marker.",
                supported_field_types=(FieldType.ENUM,),
                supported_locations=(target.location,),
                output_payload_kind=PayloadKind.INVALID,
                safe_label="safe_enum_invalid_marker",
                risk_level="low",
                mutate=lambda _context: "yslfuzz_invalid_enum",
            )
            candidates.append((target, operator, "yslfuzz_invalid_enum"))
        return candidates

    def _constant_mutator(self, value: Any) -> Callable[[MutationContext], Any]:
        def mutate(_context: MutationContext) -> Any:
            return value

        return mutate

    def _mutated_payload(
        self,
        payload: PayloadCandidate,
        target: MutationTarget,
        operator: MutationOperator,
        value: Any,
    ) -> PayloadCandidate:
        mutated = payload.model_copy(
            deep=True,
            update={
                "payload_id": self._payload_id(payload, target, operator),
                "payload_kind": operator.output_payload_kind,
                "attack_category": operator.attack_category,
                "parent_payload_id": payload.payload_id,
                "generation_strategy": f"mutation_{operator.output_payload_kind.value.lower()}_{operator.name}",
                "seed": self.config.random_seed or payload.seed,
            },
        )
        mutated.metadata.update(payload.metadata)
        mutated.metadata.update(
            {
                "mutation_name": operator.name,
                "target_field": target.name,
                "target_location": target.location.value,
                "original_field_type": target.field_type.value,
                "mutated_payload_kind": operator.output_payload_kind.value,
                "safety_label": operator.safe_label,
                "risk_level": operator.risk_level,
                "target_sensitive": target.sensitive,
            }
        )
        self._apply_value(mutated, target, value)
        return mutated

    def _apply_value(self, payload: PayloadCandidate, target: MutationTarget, value: Any) -> None:
        if target.location == ParameterLocation.BODY and isinstance(payload.body, dict):
            payload.body[target.name] = value
            return
        for parameter in payload.parameters:
            if parameter.location == target.location and parameter.name == target.name:
                parameter.value = value
                parameter.mutation_applied = True
                parameter.sensitive = target.sensitive
                if target.location == ParameterLocation.HEADER:
                    payload.headers[target.name] = value
                if target.location == ParameterLocation.COOKIE:
                    payload.cookies[target.name] = value
                return

    def _context(self, target: MutationTarget) -> MutationContext:
        return MutationContext(
            field_name=target.name,
            field_type=target.field_type,
            value=target.value,
            constraints=self._constraint_map(target.constraints),
            nullable=target.nullable,
            required=target.required,
            nested_fields={field.name: field.field_type for field in target.nested_fields},
        )

    def _allow_null_operator(self, target: MutationTarget) -> bool:
        if not self.config.allow_null_mutations:
            return False
        if target.nullable:
            return True
        return PayloadKind.INVALID in self.config.enabled_payload_kinds or PayloadKind.BOUNDARY in self.config.enabled_payload_kinds

    def _constraint_map(self, constraints: tuple[Constraint, ...]) -> dict[str, Any]:
        mapped: dict[str, Any] = {}
        for constraint in constraints:
            if constraint.constraint_type == ConstraintType.MIN_LENGTH:
                mapped["min_length"] = constraint.value
            elif constraint.constraint_type == ConstraintType.MAX_LENGTH:
                mapped["max_length"] = constraint.value
            elif constraint.constraint_type == ConstraintType.MIN_VALUE:
                mapped["min_value"] = constraint.value
            elif constraint.constraint_type == ConstraintType.MAX_VALUE:
                mapped["max_value"] = constraint.value
            elif constraint.constraint_type == ConstraintType.ENUM:
                mapped["enum"] = constraint.value
        return mapped

    def _enum_values(self, constraints: tuple[Constraint, ...]) -> list[Any]:
        values = self._constraint_map(constraints).get("enum", [])
        return list(values) if isinstance(values, list) else []

    def _body_field_map(self, endpoint: Endpoint) -> dict[str, FieldDefinition]:
        if endpoint.request_body is None:
            return {}
        return {field.name: field for field in endpoint.request_body.fields}

    def _infer_field_type(self, value: Any) -> FieldType:
        if isinstance(value, bool):
            return FieldType.BOOLEAN
        if isinstance(value, int):
            return FieldType.INTEGER
        if isinstance(value, float):
            return FieldType.FLOAT
        if isinstance(value, dict):
            return FieldType.OBJECT
        if isinstance(value, list):
            return FieldType.ARRAY
        return FieldType.UNKNOWN

    def _auth_header(self, location: ParameterLocation, name: str) -> bool:
        return location == ParameterLocation.HEADER and is_sensitive_key(name)

    def _payload_id(
        self,
        payload: PayloadCandidate,
        target: MutationTarget,
        operator: MutationOperator,
    ) -> str:
        safe_target = target.target_path.replace(".", "_").replace("-", "_").lower()
        return f"payload_mutation_{payload.payload_id}_{operator.name}_{safe_target}"
