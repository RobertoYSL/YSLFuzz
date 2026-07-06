"""Safe GraphQL attack-classified payload generation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from yslfuzz.discovery.graphql.models import GraphQLOperation, GraphQLSchema
from yslfuzz.models.enums import AttackCategory, PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.payloads.graphql.mutation_config import GraphQLMutationConfig


GRAPHQL_ATTACK_GENERATION_VERSION = "0.1.0"


class GraphQLAttackPayloadGenerator:
    """Generate inert GraphQL ATTACK-classified probes."""

    def __init__(self, config: GraphQLMutationConfig | None = None) -> None:
        self.config = config or GraphQLMutationConfig()

    def generate(
        self,
        schema: GraphQLSchema,
        valid_payloads: list[PayloadCandidate],
    ) -> list[PayloadCandidate]:
        """Generate configured safe attack-classified payloads."""
        if not self.config.include_attack_payloads:
            return []
        generated: list[PayloadCandidate] = []
        for payload in valid_payloads:
            if len(generated) >= self.config.max_attack_payloads_per_operation * max(1, len(valid_payloads)):
                break
            operation = self._operation_for_payload(schema, payload)
            operation_payloads = self._generate_for_payload(payload, operation)
            generated.extend(operation_payloads[: self.config.max_attack_payloads_per_operation])
        if self.config.allow_introspection_probe and self._introspection_category_enabled():
            generated.append(self._introspection_payload(schema))
        return generated

    def _generate_for_payload(
        self,
        payload: PayloadCandidate,
        operation: GraphQLOperation | None,
    ) -> list[PayloadCandidate]:
        generated: list[PayloadCandidate] = []
        if self._category_enabled(AttackCategory.INPUT_VALIDATION):
            invalid = self._variable_probe(
                payload,
                AttackCategory.INPUT_VALIDATION,
                operator="attack_input_validation_wrong_type",
                marker={"yslfuzz_input_validation_probe": True},
                safety_label="inert_input_validation_probe",
                target_variable=self._first_variable(payload),
            )
            if invalid is not None:
                generated.append(invalid)
        if self.config.allow_error_leakage_probe and self._category_enabled(
            AttackCategory.INFORMATION_DISCLOSURE
        ):
            generated.append(self._unknown_field_probe(payload))
        if self.config.allow_reflection_probe and self._category_enabled(AttackCategory.XSS):
            reflection = self._variable_probe(
                payload,
                AttackCategory.XSS,
                operator="attack_reflection_marker",
                marker=self.config.inert_reflection_marker,
                safety_label="inert_reflection_probe",
                target_variable=self._first_string_like_variable(payload),
                inert_marker=self.config.inert_reflection_marker,
            )
            if reflection is not None:
                generated.append(reflection)
        if self._category_enabled(AttackCategory.MASS_ASSIGNMENT):
            mass_assignment = self._mass_assignment_probe(payload)
            if mass_assignment is not None:
                generated.append(mass_assignment)
        for category, marker, operator, label in (
            (
                AttackCategory.SQL_INJECTION,
                self.config.inert_sql_marker,
                "attack_sql_inert_marker",
                "inert_sql_marker_probe",
            ),
            (
                AttackCategory.NOSQL_INJECTION,
                self.config.inert_nosql_marker,
                "attack_nosql_inert_marker",
                "inert_nosql_marker_probe",
            ),
            (
                AttackCategory.COMMAND_INJECTION,
                self.config.inert_command_marker,
                "attack_command_inert_marker",
                "inert_command_marker_probe",
            ),
            (
                AttackCategory.SSRF,
                self.config.inert_ssrf_marker,
                "attack_ssrf_inert_marker",
                "inert_ssrf_marker_probe",
            ),
        ):
            if self._category_enabled(category):
                marker_probe = self._variable_probe(
                    payload,
                    category,
                    operator=operator,
                    marker=marker,
                    safety_label=label,
                    target_variable=self._first_string_like_variable(payload),
                    inert_marker=marker,
                )
                if marker_probe is not None:
                    generated.append(marker_probe)
        del operation
        return generated

    def _variable_probe(
        self,
        payload: PayloadCandidate,
        category: AttackCategory,
        *,
        operator: str,
        marker: Any,
        safety_label: str,
        target_variable: str | None,
        inert_marker: str | None = None,
    ) -> PayloadCandidate | None:
        if target_variable is None or not isinstance(payload.body, dict):
            return None
        body = deepcopy(payload.body)
        variables = deepcopy(body.get("variables", {}))
        if not isinstance(variables, dict) or target_variable not in variables:
            return None
        variables[target_variable] = marker
        body["variables"] = variables
        return self._attack_payload(
            payload,
            body,
            category,
            operator=operator,
            target_variable=target_variable,
            target_path=target_variable,
            safety_label=safety_label,
            inert_marker=inert_marker,
        )

    def _unknown_field_probe(self, payload: PayloadCandidate) -> PayloadCandidate:
        body = deepcopy(payload.body) if isinstance(payload.body, dict) else {}
        query = str(body.get("query", ""))
        body["query"] = self._inject_unknown_field(query)
        return self._attack_payload(
            payload,
            body,
            AttackCategory.INFORMATION_DISCLOSURE,
            operator="attack_unknown_field_error_probe",
            target_variable=None,
            target_path="query",
            safety_label="inert_error_leakage_probe",
            inert_marker="yslfuzz_unknown_field",
        )

    def _mass_assignment_probe(self, payload: PayloadCandidate) -> PayloadCandidate | None:
        if not isinstance(payload.body, dict):
            return None
        body = deepcopy(payload.body)
        variables = deepcopy(body.get("variables", {}))
        if not isinstance(variables, dict):
            return None
        target_variable = self._first_object_variable(variables)
        if target_variable is None:
            return None
        value = variables[target_variable]
        if not isinstance(value, dict):
            return None
        value[self.config.inert_extra_field_name] = self.config.inert_extra_field_value
        body["variables"] = variables
        return self._attack_payload(
            payload,
            body,
            AttackCategory.MASS_ASSIGNMENT,
            operator="attack_mass_assignment_extra_field",
            target_variable=target_variable,
            target_path=f"{target_variable}.{self.config.inert_extra_field_name}",
            safety_label="inert_mass_assignment_probe",
            inert_marker=self.config.inert_extra_field_name,
        )

    def _introspection_payload(self, schema: GraphQLSchema) -> PayloadCandidate:
        category = AttackCategory.GRAPHQL_INTROSPECTION_ABUSE
        return PayloadCandidate(
            endpoint_id=f"{schema.schema_id}:query:__schema",
            payload_kind=PayloadKind.ATTACK,
            attack_category=category,
            content_type="application/json",
            body={
                "query": (
                    "query YSLFuzzIntrospection { "
                    "__schema { queryType { name } mutationType { name } } }"
                ),
                "variables": {},
                "operationName": "YSLFuzzIntrospection",
            },
            generation_strategy="graphql_attack_probe_mvp",
            seed=self.config.seed,
            metadata={
                "api_style": "GRAPHQL",
                "graphql_operation_name": "YSLFuzzIntrospection",
                "graphql_operation_field_name": "__schema",
                "graphql_operation_type": "query",
                "graphql_mutation_operator": "attack_introspection_probe",
                "graphql_target_variable": None,
                "graphql_target_path": "query.__schema",
                "graphql_original_type": "Query",
                "graphql_mutated_type": "Query",
                "attack_category": category.value,
                "safety_label": "inert_introspection_probe",
                "risk_level": "low",
                "inert_marker": "__schema",
                "redaction_applied": True,
                "graphql_attack_generation_version": GRAPHQL_ATTACK_GENERATION_VERSION,
            },
        )

    def _attack_payload(
        self,
        parent: PayloadCandidate,
        body: dict[str, Any],
        category: AttackCategory,
        *,
        operator: str,
        target_variable: str | None,
        target_path: str,
        safety_label: str,
        inert_marker: str | None,
    ) -> PayloadCandidate:
        return PayloadCandidate(
            endpoint_id=parent.endpoint_id,
            payload_kind=PayloadKind.ATTACK,
            attack_category=category,
            content_type=parent.content_type,
            body=body,
            generation_strategy="graphql_attack_probe_mvp",
            seed=self.config.seed,
            parent_payload_id=parent.payload_id,
            metadata={
                **parent.metadata,
                "api_style": "GRAPHQL",
                "graphql_mutation_operator": operator,
                "graphql_target_variable": target_variable,
                "graphql_target_path": target_path,
                "graphql_original_type": "GraphQL",
                "graphql_mutated_type": "GraphQL",
                "attack_category": category.value,
                "safety_label": safety_label,
                "risk_level": "low",
                "inert_marker": inert_marker,
                "redaction_applied": True,
                "graphql_attack_generation_version": GRAPHQL_ATTACK_GENERATION_VERSION,
            },
        )

    def _operation_for_payload(
        self,
        schema: GraphQLSchema,
        payload: PayloadCandidate,
    ) -> GraphQLOperation | None:
        name = payload.metadata.get("graphql_operation_field_name")
        operation_type = payload.metadata.get("graphql_operation_type")
        if not isinstance(name, str) or not isinstance(operation_type, str):
            return None
        return next(
            (
                operation
                for operation in schema.operations
                if operation.name == name and operation.operation_type.value == operation_type
            ),
            None,
        )

    def _category_enabled(self, category: AttackCategory) -> bool:
        return category in self.config.enabled_attack_category_set()

    def _introspection_category_enabled(self) -> bool:
        if self.config.enabled_attack_categories is None:
            return True
        return AttackCategory.GRAPHQL_INTROSPECTION_ABUSE in self.config.enabled_attack_category_set()

    def _first_variable(self, payload: PayloadCandidate) -> str | None:
        names = payload.metadata.get("graphql_variable_names")
        if isinstance(names, list):
            return str(names[0]) if names else None
        if isinstance(payload.body, dict) and isinstance(payload.body.get("variables"), dict):
            variables = payload.body["variables"]
            return next(iter(variables), None)
        return None

    def _first_string_like_variable(self, payload: PayloadCandidate) -> str | None:
        if not isinstance(payload.body, dict) or not isinstance(payload.body.get("variables"), dict):
            return None
        variables = payload.body["variables"]
        for name, value in variables.items():
            if isinstance(value, str):
                return str(name)
            if isinstance(value, dict):
                nested = self._first_nested_string_path(str(name), value)
                if nested is not None:
                    return nested
        return self._first_variable(payload)

    def _first_nested_string_path(self, prefix: str, value: dict[str, Any]) -> str | None:
        del prefix, value
        return None

    def _first_object_variable(self, variables: dict[str, Any]) -> str | None:
        for name, value in variables.items():
            if isinstance(value, dict):
                return str(name)
        return None

    def _inject_unknown_field(self, query: str) -> str:
        marker = "yslfuzz_unknown_field"
        index = query.rfind("}")
        if index == -1:
            return f"query YSLFuzzUnknownField {{ {marker} }}"
        return f"{query[:index]} {marker} {query[index:]}"
