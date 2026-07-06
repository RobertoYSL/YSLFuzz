import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class GraphQLPipelineFakeHttpExecutor:
    calls: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: Any,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
        auth_material: Any = None,
    ) -> ExecutionResult:
        del scan_run_id, timeout_seconds, auth_material
        self.calls.append(request_record.url)
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"data":{"user":{"id":"yslfuzz-id-001"}}}',
            body_size_bytes=43,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
        )


def test_graphql_execution_pipeline_writes_report_with_request_and_response_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLPipelineFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLPipelineFakeHttpExecutor)
    output_path = tmp_path / "graphql-report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--output",
            str(output_path),
            "--graphql-max-requests",
            "2",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert len(GraphQLPipelineFakeHttpExecutor.calls) == 2
    assert report["metrics"]["total_requests"] == 2
    assert report["metrics"]["successful_requests"] == 2
    assert report["metadata"]["graphql_execution"]["graphql_requests_executed"] == 2
    assert report["metadata"]["graphql_execution"]["graphql_responses_received"] == 2
