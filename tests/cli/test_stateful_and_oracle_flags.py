"""Tests for stateful workflows, dynamic auth, and oracle flags in CLI."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import (
    ExecutionResult,
    ExecutionStatus,
    RequestRecord,
    ResponseRecord,
)

EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")
CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class StatefulFakeHttpExecutor:
    calls: list[str] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: RequestRecord,
        scan_run_id: str = "test",
        timeout_seconds: float = 10.0,
        **kwargs: Any,
    ) -> ExecutionResult:
        StatefulFakeHttpExecutor.calls.append(f"{request_record.method.value} {request_record.url}")
        resp = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            headers={"Content-Type": "application/json"},
            cookies={},
            body_preview='{"user_id": 42, "id": 42, "email": "test@example.com"}',
            body_hash="hash",
            body_size_bytes=64,
            response_time_ms=5.0,
        )
        self.response_records[resp.response_id] = resp
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=resp.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


def test_cli_stateful_flag_in_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--stateful" in captured.out
    assert "--enable-workflows" in captured.out
    assert "--auth-login-url" in captured.out
    assert "--auth-user2-bearer-env" in captured.out
    assert "--enable-bola-check" in captured.out


def test_cli_stateful_scan_dry_run(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"
    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://example.com/api",
            "--output",
            str(output_path),
            "--dry-run",
            "--stateful",
        ]
    )
    assert exit_code == 0
    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    metadata = data.get("metadata", {})
    assert "stateful_workflows" in metadata
    assert metadata["stateful_workflows"]["enabled"] is True


def test_cli_stateful_scan_with_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    StatefulFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", StatefulFakeHttpExecutor)

    output_path = tmp_path / "report.json"
    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://example.com/api",
            "--output",
            str(output_path),
            "--stateful",
        ]
    )
    assert exit_code == 0
    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["metrics"]["successful_requests"] > 0
    assert len(StatefulFakeHttpExecutor.calls) > 0
    metadata = data.get("metadata", {})
    assert metadata["stateful_workflows"]["enabled"] is True


def test_cli_bola_check_with_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    StatefulFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", StatefulFakeHttpExecutor)
    monkeypatch.setenv("PRIMARY_TOKEN", "user1-token")
    monkeypatch.setenv("SECONDARY_TOKEN", "user2-token")

    output_path = tmp_path / "report.json"
    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://example.com/api",
            "--output",
            str(output_path),
            "--auth-bearer-env",
            "PRIMARY_TOKEN",
            "--auth-user2-bearer-env",
            "SECONDARY_TOKEN",
            "--enable-bola-check",
        ]
    )
    assert exit_code == 0
    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["metrics"]["successful_requests"] > 0
    assert len(StatefulFakeHttpExecutor.calls) > 0
