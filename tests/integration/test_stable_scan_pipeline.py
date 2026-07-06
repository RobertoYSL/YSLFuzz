import importlib
import json
from pathlib import Path
from typing import Any

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class StableScanFakeHttpExecutor:
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
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"ok":true}',
            body_size_bytes=11,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
        )


def test_stable_scan_pipeline_writes_stability_summary(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", StableScanFakeHttpExecutor)
    output_path = tmp_path / "report.json"

    assert CLI_MAIN.main(
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
        ]
    ) == 0

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["stability_summary"]["scan_status"] == "completed"
    assert report["stability_summary"]["planned_requests"] == 1

