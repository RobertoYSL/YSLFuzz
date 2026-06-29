import importlib
import json
from pathlib import Path

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, RequestRecord, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")
EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


class FakeHttpExecutor:
    calls: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: RequestRecord,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
    ) -> ExecutionResult:
        self.calls.append(str(request_record.payload_id))
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"ok":true}',
            body_hash="hash",
            body_size_bytes=11,
            response_time_ms=1.0,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


def test_mutation_execution_opt_in_uses_mock_executor_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    FakeHttpExecutor.calls = []
    monkeypatch.setattr("socket.create_connection", fail_network_call)
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    output_path = tmp_path / "report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://testserver.local",
            "--output",
            str(output_path),
            "--include-mutated-payloads",
            "--execute-mutations",
            "--i-understand-mutation-execution-is-authorized",
            "--max-requests",
            "4",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert len(FakeHttpExecutor.calls) > 1
    assert report["metrics"]["mutated_payloads_executed"] > 0
    assert report["payload_generation_summary"]["attack_execution_enabled"] is False
