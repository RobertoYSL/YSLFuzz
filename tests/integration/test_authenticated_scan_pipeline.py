import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class PipelineAuthFakeHttpExecutor:
    sent_authorization: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: Any,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
        auth_material: Any = None,
    ) -> ExecutionResult:
        del timeout_seconds
        if auth_material is not None:
            self.sent_authorization.append(auth_material.headers_for_send()["Authorization"])
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview="ok",
            body_hash="hash",
            body_size_bytes=2,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id},
        )


def test_authenticated_scan_pipeline_redacts_auth_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_PIPELINE")
    PipelineAuthFakeHttpExecutor.sent_authorization = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", PipelineAuthFakeHttpExecutor)
    output_path = tmp_path / "report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            "examples/openapi/simple_users_api.yaml",
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--max-requests",
            "1",
            "--auth-bearer-env",
            "YSLFUZZ_TOKEN",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert PipelineAuthFakeHttpExecutor.sent_authorization == ["Bearer SENTINEL_PIPELINE"]
    assert report["metadata"]["authentication_enabled"] is True
    assert report["metadata"]["authentication_types"] == ["bearer"]
    assert "SENTINEL_PIPELINE" not in output_path.read_text(encoding="utf-8")
