"""Tests for CLI scan presets, safety confirmation, and Markdown reporting."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.execution import AttackExecutionBundle
from yslfuzz.models import (
    ApiStyle,
    ExecutionResult,
    ExecutionStatus,
    HttpMethod,
    RequestRecord,
    ResponseRecord,
)
from yslfuzz.models.schema import Endpoint


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")
CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class FakeHttpExecutor:
    calls: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: RequestRecord,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
        auth_material: Any = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        del auth_material, kwargs
        self.calls.append(f"{request_record.method.value} {request_record.url}")
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"ok":true}',
            body_hash="fake-hash",
            body_size_bytes=11,
            response_time_ms=5.0,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


class FakeAttackExecutor:
    calls: list[int] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def execute_plan(
        self,
        plan: Any,
        endpoint: Any,
        target: Any,
        scan_run_id: str,
        session_state: Any = None,
        timeout_seconds: float = 10.0,
        dry_run: bool = False,
    ) -> AttackExecutionBundle:
        del endpoint, target, scan_run_id, session_state, timeout_seconds
        self.calls.append(len(plan.payloads))
        if dry_run or not plan.payloads:
            return AttackExecutionBundle()
        request = RequestRecord(
            scan_run_id="scan_1",
            endpoint_id=plan.endpoint_id,
            payload_id=plan.payloads[0].payload_id,
            method=HttpMethod.GET,
            url="http://localhost:8000/users",
        )
        response = ResponseRecord(
            request_id=request.request_id,
            status_code=500,
            body_preview="Unhandled Exception probe",
            body_hash="attack-hash",
            body_size_bytes=32,
            response_time_ms=10.0,
        )
        return AttackExecutionBundle(
            request_records=[request],
            response_records=[response],
            execution_results=[
                ExecutionResult(
                    request_id=request.request_id,
                    response_id=response.response_id,
                    status=ExecutionStatus.COMPLETED,
                )
            ],
        )


def test_preset_quick_configures_fast_stateless_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    output_path = tmp_path / "report_quick.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--preset",
            "quick",
        ]
    )

    assert exit_code == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["metrics"]["attack_payloads_generated"] == 0
    assert report["metrics"]["mutated_payloads_generated"] == 0
    assert not report["metadata"].get("stateful_workflows", {}).get("enabled", False)


def test_preset_standard_enables_stateful_workflows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    output_path = tmp_path / "report_standard.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--preset",
            "standard",
        ]
    )

    assert exit_code == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["metadata"].get("stateful_workflows", {}).get("enabled") is True
    assert report["metrics"]["attack_payloads_generated"] == 0


def test_preset_deep_requires_confirmation_or_yes_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    FakeAttackExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    monkeypatch.setattr(CLI_MAIN, "AttackExecutor", FakeAttackExecutor)
    output_path = tmp_path / "report_deep.json"

    # Non-interactive without -y or --yes should fail safely
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "scan",
                "--openapi",
                str(EXAMPLE_SCHEMA),
                "--base-url",
                "http://localhost:8000",
                "--output",
                str(output_path),
                "--preset",
                "deep",
            ]
        )
    assert exc_info.value.code == 1

    # With -y / --yes flag, it executes fully
    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--preset",
            "deep",
            "-y",
        ]
    )
    assert exit_code == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["metrics"]["attack_payloads_generated"] > 0
    assert report["metrics"]["mutated_payloads_generated"] > 0
    assert report["metadata"]["attack_execution_enabled"] is True
    assert report["metadata"]["mutation_execution_enabled"] is True


def test_interactive_confirmation_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    FakeAttackExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    monkeypatch.setattr(CLI_MAIN, "AttackExecutor", FakeAttackExecutor)

    # Mock sys.stdin.isatty to True
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    # 1. User confirms with 'y'
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    out_y = tmp_path / "report_y.json"
    exit_code_y = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(out_y),
            "--preset",
            "deep",
        ]
    )
    assert exit_code_y == 0
    assert out_y.exists()

    # 2. User declines with 'n'
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    out_n = tmp_path / "report_n.json"
    exit_code_n = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(out_n),
            "--preset",
            "deep",
        ]
    )
    assert exit_code_n == 0
    assert not out_n.exists()


def test_scan_with_markdown_report_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(json_path),
            "--markdown",
            str(md_path),
            "--preset",
            "standard",
        ]
    )

    assert exit_code == 0
    assert json_path.exists()
    assert md_path.exists()
    md_content = md_path.read_text(encoding="utf-8")
    assert "# YSLFuzz Scan Report" in md_content
    assert "## Target" in md_content
    assert "## Scan Summary" in md_content
    assert "## Stateful Workflows" in md_content


def test_print_summary_terminal_box(capsys: pytest.CaptureFixture[str]) -> None:
    from yslfuzz.cli.scan_args import _print_summary
    from yslfuzz.models import FindingConfidence, FindingSeverity, SecurityFinding

    dummy_finding = SecurityFinding(
        finding_id="f1",
        scan_run_id="run_1",
        endpoint_id="ep_1",
        title="SQL Injection Vulnerability",
        description="SQL error detected",
        attack_category="SQL_INJECTION",  # type: ignore[arg-type]
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        request_ids=["req_1"],
        evidence=[{"description": "leak", "evidence_type": "status_code", "source": "test"}],  # type: ignore[list-item]
    )
    dummy_endpoint = Endpoint(
        endpoint_id="ep_1",
        api_schema_id="schema_1",
        name="get_users",
        api_style=ApiStyle.REST,
        path="/api/users",
        method=HttpMethod.GET,
    )

    _print_summary(
        output_path=Path("scan.json"),
        markdown_path=Path("scan.md"),
        total_endpoints=1,
        payloads_generated=10,
        valid_payloads_generated=2,
        boundary_payloads_generated=3,
        invalid_payloads_generated=2,
        mutated_payloads_generated=1,
        attack_payloads_generated=2,
        total_requests=8,
        successful_requests=8,
        failed_requests=0,
        findings_total=1,
        dry_run=False,
        findings=[dummy_finding],
        endpoints=[dummy_endpoint],
        workflow_stats={"workflows_executed": 1, "workflows_detected": 2, "known_values_extracted": 3},
        target_url="http://target.local",
        preset="deep",
    )

    captured = capsys.readouterr().out
    assert "YSLFUZZ SCAN SUMMARY" in captured
    assert "Target:            http://target.local" in captured
    assert "preset: deep" in captured
    assert "🔴 HIGH" in captured
    assert "GET /api/users" in captured
    assert "JSON Report:       scan.json" in captured
    assert "Markdown Report:   scan.md" in captured
