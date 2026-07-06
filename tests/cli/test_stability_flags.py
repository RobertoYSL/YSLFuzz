import importlib
import json
from pathlib import Path
from typing import Any

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class StabilityFakeHttpExecutor:
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
        self.calls.append(str(request_record.endpoint_id))
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


def test_cli_exposes_stability_flags_in_scan_help(capsys: Any) -> None:
    try:
        CLI_MAIN.main(["scan", "--help"])
    except SystemExit:
        pass
    output = capsys.readouterr().out

    assert "--rate-limit-rps" in output
    assert "--max-requests-per-endpoint" in output
    assert "--max-scan-duration-seconds" in output
    assert "--retry" in output
    assert "--progress" in output


def test_cli_parses_stability_flags_and_reports_summary(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    StabilityFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", StabilityFakeHttpExecutor)
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
            "2",
            "--max-requests-per-endpoint",
            "1",
            "--rate-limit-rps",
            "2.0",
            "--min-request-delay-ms",
            "5",
            "--max-scan-duration-seconds",
            "60",
            "--retry",
            "--max-retries",
            "1",
            "--retry-status-code",
            "429,503",
            "--progress",
        ]
    ) == 0

    report = json.loads(output_path.read_text(encoding="utf-8"))
    stability = report["stability_summary"]
    assert stability["max_requests"] == 2
    assert stability["max_requests_per_endpoint"] == 1
    assert stability["rate_limit_rps"] == 2.0
    assert stability["retry_enabled"] is True
    assert stability["max_retries"] == 1

