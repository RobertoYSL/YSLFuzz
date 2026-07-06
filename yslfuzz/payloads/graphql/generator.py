"""GraphQL valid payload generation."""

from yslfuzz.discovery.graphql.models import GraphQLOperation, GraphQLOperationType, GraphQLSchema
from yslfuzz.models.enums import ApiStyle, PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.payloads.graphql.config import GraphQLPayloadConfig
from yslfuzz.payloads.graphql.operation_builder import GraphQLOperationBuilder


GRAPHQL_PAYLOAD_GENERATION_VERSION = "0.1.0"


class GraphQLPayloadGenerator:
    """Generate deterministic safe GraphQL operation payload candidates."""

    def __init__(
        self,
        config: GraphQLPayloadConfig | None = None,
        operation_builder: GraphQLOperationBuilder | None = None,
    ) -> None:
        self.config = config or GraphQLPayloadConfig()
        self.operation_builder = operation_builder or GraphQLOperationBuilder(self.config)

    def generate(self, schema: GraphQLSchema) -> list[PayloadCandidate]:
        """Generate bounded valid GraphQL payloads without executing them."""
        payloads: list[PayloadCandidate] = []
        for operation in self._selected_operations(schema):
            if self.config.max_operations is not None and len(payloads) >= self.config.max_operations:
                break
            operation_payload = self.operation_builder.build(operation, schema)
            endpoint_id = self._endpoint_id(operation, schema)
            payloads.append(
                PayloadCandidate(
                    endpoint_id=endpoint_id,
                    payload_kind=PayloadKind.VALID,
                    content_type="application/json",
                    body=operation_payload.body(),
                    generation_strategy="graphql_valid_schema_mvp",
                    seed=self.config.seed,
                    metadata={
                        "api_style": ApiStyle.GRAPHQL.value,
                        "graphql_operation_name": operation_payload.operationName,
                        "graphql_operation_field_name": operation_payload.operation_field_name,
                        "graphql_operation_type": operation_payload.operation_type,
                        "graphql_return_type": operation_payload.return_type,
                        "graphql_variable_names": operation_payload.variable_names,
                        "graphql_selection_depth": operation_payload.selection_depth,
                        "graphql_source_schema_id": schema.schema_id,
                        "graphql_payload_generation_version": GRAPHQL_PAYLOAD_GENERATION_VERSION,
                        "execution_enabled": False,
                    },
                )
            )
        return payloads

    def _selected_operations(self, schema: GraphQLSchema) -> list[GraphQLOperation]:
        allowed: set[GraphQLOperationType] = set()
        if self.config.include_queries:
            allowed.add(GraphQLOperationType.QUERY)
        if self.config.include_mutations:
            allowed.add(GraphQLOperationType.MUTATION)
        if self.config.include_subscriptions:
            allowed.add(GraphQLOperationType.SUBSCRIPTION)
        return [operation for operation in schema.operations if operation.operation_type in allowed]

    def _endpoint_id(self, operation: GraphQLOperation, schema: GraphQLSchema) -> str:
        return f"{schema.schema_id}:{operation.operation_type.value}:{operation.name}"
