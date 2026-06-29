"""Workflow builder for simple producer-consumer dependencies."""

from yslfuzz.dependency.heuristics import resource_name_for_endpoint, response_identifier_fields
from yslfuzz.models.dependency import (
    DependencyGraph,
    ValueExtractor,
    VariableBinding,
    Workflow,
    WorkflowStep,
)
from yslfuzz.models.enums import FindingConfidence, HttpMethod
from yslfuzz.models.schema import ApiSchema, Endpoint


class WorkflowBuilder:
    """Build deterministic two-step workflows from dependency graphs."""

    def build_workflows(
        self,
        api_schema: ApiSchema,
        dependency_graph: DependencyGraph,
    ) -> list[Workflow]:
        """Build simple producer endpoint -> consumer endpoint workflows."""
        endpoints_by_id = {endpoint.endpoint_id: endpoint for endpoint in api_schema.endpoints}
        producers = self._producer_endpoint_ids(dependency_graph)
        consumers_by_value = self._consumer_endpoint_ids_by_value(dependency_graph)

        workflows: list[Workflow] = []
        for value_node_id, producer_endpoint_ids in sorted(producers.items()):
            for producer_endpoint_id in sorted(producer_endpoint_ids):
                producer = endpoints_by_id.get(producer_endpoint_id)
                if producer is None:
                    continue
                for consumer_endpoint_id in sorted(consumers_by_value.get(value_node_id, set())):
                    consumer = endpoints_by_id.get(consumer_endpoint_id)
                    if consumer is None or consumer.endpoint_id == producer.endpoint_id:
                        continue
                    workflows.append(self._workflow(producer, consumer, value_node_id))
        return workflows

    def build(
        self,
        api_schema: ApiSchema,
        dependency_graph: DependencyGraph,
    ) -> list[Workflow]:
        """Compatibility alias for build_workflows."""
        return self.build_workflows(api_schema, dependency_graph)

    def _workflow(self, producer: Endpoint, consumer: Endpoint, value_node_id: str) -> Workflow:
        resource_name = resource_name_for_endpoint(producer)
        target_name = value_node_id.removeprefix("node_value_")
        output_extractors = [
            ValueExtractor(
                extractor_id=f"extractor_{producer.endpoint_id}_{field.name}",
                source="response.body",
                expression=f"$.{field.name}",
                target_name=target_name,
            )
            for field in response_identifier_fields(producer)
        ]
        if not output_extractors:
            output_extractors = [
                ValueExtractor(
                    extractor_id=f"extractor_{producer.endpoint_id}_{target_name}",
                    source="response.body",
                    expression="$.id",
                    target_name=target_name,
                )
            ]

        input_bindings = [
            VariableBinding(
                binding_id=f"binding_{producer.endpoint_id}_{consumer.endpoint_id}_{target_name}",
                source=target_name,
                target=self._binding_target(consumer, target_name),
            )
        ]
        destructive = consumer.method in {HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH}

        return Workflow(
            workflow_id=f"workflow_{producer.endpoint_id}_{consumer.endpoint_id}_{target_name}",
            name=f"{producer.name} -> {consumer.name}",
            description=f"Create/read workflow for {resource_name}",
            steps=[
                WorkflowStep(
                    workflow_step_id=f"workflow_step_{producer.endpoint_id}_1",
                    endpoint_id=producer.endpoint_id,
                    order=1,
                    output_extractors=output_extractors,
                    expected_status_codes=[200, 201],
                ),
                WorkflowStep(
                    workflow_step_id=f"workflow_step_{consumer.endpoint_id}_2",
                    endpoint_id=consumer.endpoint_id,
                    order=2,
                    input_bindings=input_bindings,
                    expected_status_codes=[200],
                ),
            ],
            required_auth=producer.auth_required or consumer.auth_required,
            destructive=destructive,
            confidence=FindingConfidence.MEDIUM,
        )

    def _producer_endpoint_ids(self, graph: DependencyGraph) -> dict[str, set[str]]:
        endpoint_by_node_id = {
            node.node_id: node.ref_id
            for node in graph.nodes
            if node.node_type == "ENDPOINT"
        }
        producers: dict[str, set[str]] = {}
        for edge in graph.edges:
            if edge.dependency_type != "PRODUCES":
                continue
            endpoint_id = endpoint_by_node_id.get(edge.source_node_id)
            if endpoint_id is None:
                continue
            producers.setdefault(edge.target_node_id, set()).add(endpoint_id)
        return producers

    def _consumer_endpoint_ids_by_value(self, graph: DependencyGraph) -> dict[str, set[str]]:
        endpoint_by_node_id = {
            node.node_id: node.ref_id
            for node in graph.nodes
            if node.node_type == "ENDPOINT"
        }
        consumers: dict[str, set[str]] = {}
        for edge in graph.edges:
            if edge.dependency_type != "CONSUMES":
                continue
            endpoint_id = endpoint_by_node_id.get(edge.target_node_id)
            if endpoint_id is None:
                continue
            consumers.setdefault(edge.source_node_id, set()).add(endpoint_id)
        return consumers

    def _binding_target(self, consumer: Endpoint, target_name: str) -> str:
        for parameter in consumer.parameters:
            if parameter.name == "id" or parameter.name.endswith("_id"):
                return f"{parameter.location.value.lower()}.{parameter.name}"
        return f"path.{target_name}"
