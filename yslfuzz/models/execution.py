"""Execution data models."""

from datetime import datetime
from typing import Any

from pydantic import Field, field_serializer

from yslfuzz.models.base import YSLFuzzModel, prefixed_id, redact_mapping, utc_now
from yslfuzz.models.dependency import Workflow
from yslfuzz.models.enums import ExecutionStatus, HttpMethod
from yslfuzz.models.payload import PayloadCandidate


class ScanRun(YSLFuzzModel):
    scan_run_id: str = Field(default_factory=lambda: prefixed_id("scan"))
    project_id: str
    target_id: str
    scan_config_id: str
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    api_schema_id: str
    dependency_graph_id: str | None = None
    execution_plan_id: str | None = None
    summary_metrics: "ScanMetrics | None" = None


class ExecutionPlan(YSLFuzzModel):
    execution_plan_id: str = Field(default_factory=lambda: prefixed_id("execution_plan"))
    scan_run_id: str
    workflows: list[Workflow] = Field(default_factory=list)
    standalone_payloads: list[PayloadCandidate] = Field(default_factory=list)
    max_concurrency: int = 10
    estimated_request_count: int = 0
    created_at: datetime = Field(default_factory=utc_now)


class SessionState(YSLFuzzModel):
    session_state_id: str = Field(default_factory=lambda: prefixed_id("session_state"))
    cookies: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, Any] = Field(default_factory=dict)
    auth_tokens: dict[str, Any] = Field(default_factory=dict)
    last_response_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    sensitive_keys: list[str] = Field(default_factory=list)

    @field_serializer("cookies", "headers", "auth_tokens")
    def serialize_sensitive_mapping(self, values: dict[str, Any]) -> dict[str, Any]:
        return redact_mapping(values)


class RequestRecord(YSLFuzzModel):
    request_id: str = Field(default_factory=lambda: prefixed_id("request"))
    scan_run_id: str
    endpoint_id: str
    payload_id: str | None = None
    workflow_id: str | None = None
    workflow_step_id: str | None = None
    method: HttpMethod
    url: str
    headers: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    path_params: dict[str, Any] = Field(default_factory=dict)
    cookies: dict[str, Any] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    content_type: str | None = None
    sent_at: datetime = Field(default_factory=utc_now)

    @field_serializer("headers", "cookies")
    def serialize_sensitive_mapping(self, values: dict[str, Any]) -> dict[str, Any]:
        return redact_mapping(values)

    @field_serializer("body")
    def serialize_body(self, value: dict[str, Any] | str | None) -> dict[str, Any] | str | None:
        if isinstance(value, dict):
            return redact_mapping(value)
        return value


class ResponseRecord(YSLFuzzModel):
    response_id: str = Field(default_factory=lambda: prefixed_id("response"))
    request_id: str
    status_code: int
    headers: dict[str, Any] = Field(default_factory=dict)
    cookies: dict[str, Any] = Field(default_factory=dict)
    body_preview: str | None = None
    body_hash: str | None = None
    body_size_bytes: int = 0
    response_time_ms: float = 0.0
    received_at: datetime = Field(default_factory=utc_now)
    error: str | None = None

    @field_serializer("headers", "cookies")
    def serialize_sensitive_mapping(self, values: dict[str, Any]) -> dict[str, Any]:
        return redact_mapping(values)


class ExecutionResult(YSLFuzzModel):
    execution_result_id: str = Field(default_factory=lambda: prefixed_id("execution_result"))
    request_id: str
    response_id: str | None = None
    status: ExecutionStatus
    error_type: str | None = None
    error_message: str | None = None
    retry_count: int = 0


from yslfuzz.models.reporting import ScanMetrics  # noqa: E402

ScanRun.model_rebuild()
