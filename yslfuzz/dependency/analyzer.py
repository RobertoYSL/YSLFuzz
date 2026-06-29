"""Dependency graph analyzer for internal API schemas."""

from yslfuzz.dependency.heuristics import (
    canonical_identifier_key,
    consumer_body_fields,
    consumer_parameters,
    crud_dependency_type,
    resource_name_for_endpoint,
    response_identifier_fields,
    stable_key,
)
from yslfuzz.models.dependency import DependencyEdge, DependencyGraph, DependencyNode
from yslfuzz.models.enums import ApiStyle, FindingConfidence, HttpMethod
from yslfuzz.models.schema import ApiSchema, Endpoint, FieldDefinition, Parameter


class DependencyAnalyzer:
    """Infer basic endpoint, field, value, auth, and CRUD dependencies."""

    def analyze(self, api_schema: ApiSchema) -> DependencyGraph:
        """Analyze an ApiSchema and return a deterministic DependencyGraph."""
        if api_schema.api_style != ApiStyle.REST:
            return DependencyGraph(
                dependency_graph_id=self._graph_id(api_schema),
                api_schema_id=api_schema.api_schema_id,
            )

        nodes: dict[str, DependencyNode] = {}
        edges: dict[str, DependencyEdge] = {}

        for endpoint in sorted(api_schema.endpoints, key=self._endpoint_sort_key):
            endpoint_node = self._endpoint_node(endpoint)
            nodes[endpoint_node.node_id] = endpoint_node
            self._add_crud_edge(endpoint, endpoint_node, edges)
            self._add_auth_edge(endpoint, endpoint_node, nodes, edges)
            self._add_producer_edges(endpoint, endpoint_node, nodes, edges)
            self._add_consumer_edges(endpoint, endpoint_node, nodes, edges)

        return DependencyGraph(
            dependency_graph_id=self._graph_id(api_schema),
            api_schema_id=api_schema.api_schema_id,
            nodes=sorted(nodes.values(), key=lambda node: node.node_id),
            edges=sorted(edges.values(), key=lambda edge: edge.edge_id),
        )

    def _add_producer_edges(
        self,
        endpoint: Endpoint,
        endpoint_node: DependencyNode,
        nodes: dict[str, DependencyNode],
        edges: dict[str, DependencyEdge],
    ) -> None:
        if endpoint.method != HttpMethod.POST:
            return
        resource_name = resource_name_for_endpoint(endpoint)
        for field in response_identifier_fields(endpoint):
            field_node = self._field_node(endpoint, field, "response")
            value_node = self._value_node(field.name, resource_name)
            nodes[field_node.node_id] = field_node
            nodes[value_node.node_id] = value_node
            self._edge(endpoint_node, field_node, "RETURNS_ID", edges, f"POST response field {field.name}")
            self._edge(endpoint_node, value_node, "PRODUCES", edges, f"POST produces {field.name}")
            self._edge(field_node, value_node, "PRODUCES", edges, f"Field {field.name} produces value")

    def _add_consumer_edges(
        self,
        endpoint: Endpoint,
        endpoint_node: DependencyNode,
        nodes: dict[str, DependencyNode],
        edges: dict[str, DependencyEdge],
    ) -> None:
        resource_name = resource_name_for_endpoint(endpoint)
        for parameter in consumer_parameters(endpoint):
            field_node = self._parameter_field_node(endpoint, parameter)
            value_node = self._value_node(parameter.name, resource_name)
            nodes[field_node.node_id] = field_node
            nodes[value_node.node_id] = value_node
            self._edge(field_node, endpoint_node, "USES_ID", edges, f"Parameter {parameter.name}")
            self._edge(value_node, endpoint_node, "CONSUMES", edges, f"Endpoint consumes {parameter.name}")
            self._edge(value_node, field_node, "CONSUMES", edges, f"Value used by {parameter.name}")

        for field in consumer_body_fields(endpoint):
            field_node = self._field_node(endpoint, field, "request")
            value_node = self._value_node(field.name, resource_name)
            nodes[field_node.node_id] = field_node
            nodes[value_node.node_id] = value_node
            self._edge(field_node, endpoint_node, "USES_ID", edges, f"Body field {field.name}")
            self._edge(value_node, endpoint_node, "CONSUMES", edges, f"Endpoint consumes {field.name}")

    def _add_crud_edge(
        self,
        endpoint: Endpoint,
        endpoint_node: DependencyNode,
        edges: dict[str, DependencyEdge],
    ) -> None:
        dependency_type = crud_dependency_type(endpoint)
        if dependency_type is None:
            return
        self._edge(endpoint_node, endpoint_node, dependency_type, edges, endpoint.path or endpoint.name)

    def _add_auth_edge(
        self,
        endpoint: Endpoint,
        endpoint_node: DependencyNode,
        nodes: dict[str, DependencyNode],
        edges: dict[str, DependencyEdge],
    ) -> None:
        if not endpoint.auth_required:
            return
        auth_node = DependencyNode(
            node_id=f"node_auth_{self._endpoint_key(endpoint)}",
            node_type="AUTH_STATE",
            ref_id=endpoint.endpoint_id,
            label=f"auth required for {endpoint.name}",
        )
        nodes[auth_node.node_id] = auth_node
        self._edge(auth_node, endpoint_node, "REQUIRES_AUTH", edges, "Endpoint auth_required is true")

    def _endpoint_node(self, endpoint: Endpoint) -> DependencyNode:
        method = endpoint.method.value if endpoint.method else "UNKNOWN"
        return DependencyNode(
            node_id=f"node_endpoint_{self._endpoint_key(endpoint)}",
            node_type="ENDPOINT",
            ref_id=endpoint.endpoint_id,
            label=f"{method} {endpoint.path or endpoint.name}",
            metadata={"method": method, "path": endpoint.path, "name": endpoint.name},
        )

    def _field_node(self, endpoint: Endpoint, field: FieldDefinition, source: str) -> DependencyNode:
        return DependencyNode(
            node_id=f"node_field_{self._endpoint_key(endpoint)}_{source}_{stable_key(field.name)}",
            node_type="FIELD",
            ref_id=field.field_id,
            label=f"{source}.{field.name}",
            metadata={
                "endpoint_id": endpoint.endpoint_id,
                "field_name": field.name,
                "field_type": field.field_type.value,
                "source": source,
            },
        )

    def _parameter_field_node(self, endpoint: Endpoint, parameter: Parameter) -> DependencyNode:
        return DependencyNode(
            node_id=f"node_field_{self._endpoint_key(endpoint)}_parameter_{stable_key(parameter.name)}",
            node_type="FIELD",
            ref_id=parameter.parameter_id,
            label=f"parameter.{parameter.name}",
            metadata={
                "endpoint_id": endpoint.endpoint_id,
                "field_name": parameter.name,
                "field_type": parameter.field_type.value,
                "location": parameter.location.value,
                "source": "parameter",
            },
        )

    def _value_node(self, name: str, resource_name: str) -> DependencyNode:
        identifier_key = canonical_identifier_key(name, resource_name)
        return DependencyNode(
            node_id=f"node_value_{stable_key(identifier_key)}",
            node_type="VALUE",
            ref_id=identifier_key,
            label=identifier_key,
            metadata={"identifier_key": identifier_key, "resource": resource_name},
        )

    def _edge(
        self,
        source: DependencyNode,
        target: DependencyNode,
        dependency_type: str,
        edges: dict[str, DependencyEdge],
        evidence: str,
    ) -> None:
        edge_id = f"edge_{source.node_id}_{dependency_type.lower()}_{target.node_id}"
        edges[edge_id] = DependencyEdge(
            edge_id=edge_id,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            dependency_type=dependency_type,
            confidence=FindingConfidence.MEDIUM,
            evidence=evidence,
        )

    def _graph_id(self, api_schema: ApiSchema) -> str:
        return f"dependency_graph_{stable_key(api_schema.api_schema_id)}"

    def _endpoint_key(self, endpoint: Endpoint) -> str:
        method = endpoint.method.value.lower() if endpoint.method else "unknown"
        return stable_key(f"{method}_{endpoint.path or endpoint.name}")

    def _endpoint_sort_key(self, endpoint: Endpoint) -> tuple[str, str, str]:
        return (
            endpoint.path or "",
            endpoint.method.value if endpoint.method else "",
            endpoint.name,
        )
