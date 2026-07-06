"""GraphQL boundary, invalid and mutated payload generation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from yslfuzz.discovery.graphql.models import (
    GraphQLArgument,
    GraphQLInputObject,
    GraphQLOperation,
    GraphQLSchema,
    GraphQLTypeRef,
)
from yslfuzz.models.enums import PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.payloads.graphql.mutation_config import GraphQLMutationConfig
from yslfuzz.payloads.graphql.mutation_operators import (
    GraphQLMutation,
    GraphQLMutationContext,
    GraphQLMutationOperator,
    boundary_mutations,
    invalid_mutations,
    is_sensitive_variable,
    mutated_mutations,
    unwrap_non_null,
)


class GraphQLMutationEngine:
    """Generate safe GraphQL BOUNDARY, INVALID and MUTATED payload candidates."""

    def __init__(
        self,
        config: GraphQLMutationConfig | None = None,
        operator: GraphQLMutationOperator | None = None,
    ) -> None:
        self.config = config or GraphQLMutationConfig()
        self.operator = operator or GraphQLMutationOperator()

    def mutate(
        self,
        schema: GraphQLSchema,
        payloads: list[PayloadCandidate],
    ) -> list[PayloadCandidate]:
        """Generate configured non-valid GraphQL payloads from valid payloads."""
        generated: list[PayloadCandidate] = []
        for payload in payloads:
            if payload.payload_kind != PayloadKind.VALID:
                continue
            operation = self._operation_for_payload(schema, payload)
            if operation is None or not isinstance(payload.body, dict):
                continue
            variables = payload.body.get("variables", {})
            if not isinstance(variables, dict):
                continue
            payload_count = 0
            for argument in operation.arguments:
                if payload_count >= self.config.max_mutations_per_payload:
                    break
                if self._skip_argument(argument):
                    continue
                contexts = self._contexts_for_argument(argument, variables, schema)
                for context in contexts:
                    if payload_count >= self.config.max_mutations_per_payload:
                        break
                    mutations = self._mutations_for_context(context)
                    for mutation in mutations[: self.config.max_mutations_per_variable]:
                        if payload_count >= self.config.max_mutations_per_payload:
                            break
                        generated.append(self.operator.apply(payload, context, mutation))
                        payload_count += 1
        return generated

    def _mutations_for_context(self, context: GraphQLMutationContext) -> list[GraphQLMutation]:
        families: list[list[GraphQLMutation]] = []
        if self.config.include_boundary_payloads:
            families.append(boundary_mutations(context, self.config.allow_type_confusion))
        if self.config.include_invalid_payloads:
            families.append(
                invalid_mutations(
                    context,
                    allow_null_mutations=self.config.allow_null_mutations,
                    allow_type_confusion=self.config.allow_type_confusion,
                    allow_invalid_enum_values=self.config.allow_invalid_enum_values,
                )
            )
        if self.config.include_mutated_payloads:
            families.append(mutated_mutations(context, self.config.allow_type_confusion))
        shape_mutations = self._input_object_shape_mutations(context)
        if shape_mutations:
            families.append(shape_mutations)
        return self._interleave_mutation_families(families)

    def _interleave_mutation_families(
        self,
        families: list[list[GraphQLMutation]],
    ) -> list[GraphQLMutation]:
        mutations: list[GraphQLMutation] = []
        max_length = max((len(family) for family in families), default=0)
        for index in range(max_length):
            for family in families:
                if index < len(family):
                    mutations.append(family[index])
        return mutations

    def _operation_for_payload(
        self,
        schema: GraphQLSchema,
        payload: PayloadCandidate,
    ) -> GraphQLOperation | None:
        operation_name = payload.metadata.get("graphql_operation_field_name")
        operation_type = payload.metadata.get("graphql_operation_type")
        if not isinstance(operation_name, str) or not isinstance(operation_type, str):
            return None
        return next(
            (
                operation
                for operation in schema.operations
                if operation.name == operation_name and operation.operation_type.value == operation_type
            ),
            None,
        )

    def _contexts_for_argument(
        self,
        argument: GraphQLArgument,
        variables: dict[str, Any],
        schema: GraphQLSchema,
    ) -> list[GraphQLMutationContext]:
        if argument.name not in variables:
            return []
        value = variables[argument.name]
        contexts = [
            GraphQLMutationContext(
                variable_name=argument.name,
                type_ref=argument.type_ref,
                original_value=value,
                target_path=(argument.name,),
                schema=schema,
            )
        ]
        contexts.extend(
            self._nested_contexts(
                argument.name,
                argument.type_ref,
                value,
                (argument.name,),
                schema,
                depth=0,
            )
        )
        return contexts

    def _nested_contexts(
        self,
        variable_name: str,
        type_ref: GraphQLTypeRef,
        value: Any,
        path: tuple[str, ...],
        schema: GraphQLSchema,
        *,
        depth: int,
    ) -> list[GraphQLMutationContext]:
        if depth >= self.config.max_input_depth or not isinstance(value, dict):
            return []
        input_object = self._input_object(type_ref, schema)
        if input_object is None:
            return []
        contexts: list[GraphQLMutationContext] = []
        for field in input_object.fields:
            if field.name not in value or self._skip_argument(field):
                continue
            field_path = (*path, field.name)
            field_value = value[field.name]
            contexts.append(
                GraphQLMutationContext(
                    variable_name=variable_name,
                    type_ref=field.type_ref,
                    original_value=field_value,
                    target_path=field_path,
                    schema=schema,
                )
            )
            contexts.extend(
                self._nested_contexts(
                    variable_name,
                    field.type_ref,
                    field_value,
                    field_path,
                    schema,
                    depth=depth + 1,
                )
            )
        return contexts

    def _input_object_shape_mutations(
        self,
        context: GraphQLMutationContext,
    ) -> list[GraphQLMutation]:
        if not isinstance(context.original_value, dict) or len(context.target_path) != 1:
            return []
        input_object = self._input_object(context.type_ref, context.schema)
        if input_object is None:
            return []
        mutations: list[GraphQLMutation] = []
        if self.config.include_invalid_payloads and self.config.allow_extra_input_fields:
            extra_value = deepcopy(context.original_value)
            extra_value[self.config.inert_extra_field_name] = self.config.inert_extra_field_value
            mutations.append(
                GraphQLMutation(
                    operator="input_object_extra_field",
                    payload_kind=PayloadKind.INVALID,
                    value=extra_value,
                    mutated_type="input_object",
                    safety_label="schema_invalid",
                    inert_marker=self.config.inert_extra_field_name,
                )
            )
        if self.config.include_invalid_payloads and self.config.allow_missing_required_fields:
            for field in input_object.fields:
                if field.type_ref.is_non_null() and field.name in context.original_value:
                    missing_value = deepcopy(context.original_value)
                    missing_value.pop(field.name, None)
                    mutations.append(
                        GraphQLMutation(
                            operator="input_object_missing_required_field",
                            payload_kind=PayloadKind.INVALID,
                            value=missing_value,
                            mutated_type="input_object",
                            safety_label="schema_invalid",
                        )
                    )
                    break
        return mutations

    def _input_object(
        self,
        type_ref: GraphQLTypeRef,
        schema: GraphQLSchema,
    ) -> GraphQLInputObject | None:
        name = unwrap_non_null(type_ref).named_type()
        if name is None:
            return None
        return next((input_object for input_object in schema.input_objects if input_object.name == name), None)

    def _skip_argument(self, argument: GraphQLArgument) -> bool:
        return (
            not self.config.include_sensitive_fields
            and is_sensitive_variable(argument.name, argument.metadata)
        )
