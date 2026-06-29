import json
import importlib
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.execution import AttackExecutionBundle
from yslfuzz.models import ExecutionResult, ExecutionStatus, HttpMethod, RequestRecord, ResponseRecord


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
    ) -> ExecutionResult:
        self.calls.append(f"{request_record.method.value} {request_record.url}")
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"ok":true}',
            body_hash="baseline-hash",
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
            body_preview="Unhandled Exception yslfuzz_probe token=raw-token-value",
            body_hash="attack-hash",
            body_size_bytes=64,
            response_time_ms=20.0,
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


def test_include_attack_payloads_does_not_execute_attacks_by_itself(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    FakeAttackExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    monkeypatch.setattr(CLI_MAIN, "AttackExecutor", FakeAttackExecutor)
    output_path = tmp_path / "report.json"

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--max-requests",
            "1",
            "--include-attack-payloads",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert FakeAttackExecutor.calls == []
    assert report["metrics"]["attack_payloads_generated"] > 0


def test_execute_attacks_without_authorization_flag_fails(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "scan",
                "--openapi",
                str(EXAMPLE_SCHEMA),
                "--base-url",
                "http://localhost:8000",
                "--output",
                str(tmp_path / "report.json"),
                "--include-attack-payloads",
                "--execute-attacks",
            ]
        )

    assert exc_info.value.code == 1


def test_execute_attacks_with_authorization_flag_enables_attack_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    FakeAttackExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    monkeypatch.setattr(CLI_MAIN, "AttackExecutor", FakeAttackExecutor)
    output_path = tmp_path / "report.json"

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--max-requests",
            "1",
            "--include-attack-payloads",
            "--execute-attacks",
            "--i-understand-this-is-authorized",
            "--max-attack-requests-per-endpoint",
            "1",
        ]
    )
    encoded = output_path.read_text(encoding="utf-8")

    assert FakeAttackExecutor.calls == [1]
    assert "raw-token-value" not in encoded
    assert json.loads(encoded)["findings"]


def test_dry_run_prevents_attack_execution_even_with_attack_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    FakeAttackExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    monkeypatch.setattr(CLI_MAIN, "AttackExecutor", FakeAttackExecutor)

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(tmp_path / "report.json"),
            "--dry-run",
            "--include-attack-payloads",
            "--execute-attacks",
            "--i-understand-this-is-authorized",
        ]
    )

    assert FakeHttpExecutor.calls == []
    assert FakeAttackExecutor.calls == []
