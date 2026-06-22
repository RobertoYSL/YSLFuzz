"""Dependency graph and workflow data models."""

from datetime import datetime
from typing import Any

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, utc_now
from yslfuzz.models.enums import FindingConfidence


class DependencyNode(YSLFuzzModel):
    node_id: str = Field(default_factory=lambda: prefixed_id("node"))
    node_type: str
    ref_id: str
    label: str


class DependencyEdge(YSLFuzzModel):
    edge_id: str = Field(default_factory=lambda: prefixed_id("edge"))
    source_node_id: str
    target_node_id: str
    dependency_type: str
    confidence: FindingConfidence = FindingConfidence.LOW
    evidence: str | None = None


class VariableBinding(YSLFuzzModel):
    binding_id: str = Field(default_factory=lambda: prefixed_id("binding"))
    source: str
    target: str
    value: Any | None = None


class ValueExtractor(YSLFuzzModel):
    extractor_id: str = Field(default_factory=lambda: prefixed_id("extractor"))
    source: str
    expression: str
    target_name: str


class WorkflowStep(YSLFuzzModel):
    workflow_step_id: str = Field(default_factory=lambda: prefixed_id("workflow_step"))
    endpoint_id: str
    order: int
    input_bindings: list[VariableBinding] = Field(default_factory=list)
    output_extractors: list[ValueExtractor] = Field(default_factory=list)
    expected_status_codes: list[int] = Field(default_factory=lambda: [200])
    optional: bool = False


class Workflow(YSLFuzzModel):
    workflow_id: str = Field(default_factory=lambda: prefixed_id("workflow"))
    name: str
    description: str | None = None
    steps: list[WorkflowStep] = Field(default_factory=list)
    required_auth: bool = False
    destructive: bool = False
    confidence: FindingConfidence = FindingConfidence.LOW


class DependencyGraph(YSLFuzzModel):
    dependency_graph_id: str = Field(default_factory=lambda: prefixed_id("dependency_graph"))
    api_schema_id: str
    nodes: list[DependencyNode] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
