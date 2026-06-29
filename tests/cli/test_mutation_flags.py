import importlib
import json
from pathlib import Path

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, RequestRecord, ResponseRecord


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
        self.calls.append(f"{request_record.payload_id}:{request_record.method.value} {request_record.url}")
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"ok":true}',
            body_hash="hash",
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


def test_scan_help_exposes_mutation_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--include-boundary-payloads" in output
    assert "--execute-mutations" in output
    assert "--i-understand-mutation-execution-is-authorized" in output


def test_include_boundary_invalid_and_mutated_payloads_generate_counts(tmp_path: Path) -> None:
    report = _run_cli(
        tmp_path,
        "--dry-run",
        "--include-boundary-payloads",
        "--include-invalid-payloads",
        "--include-mutated-payloads",
    )

    assert report["metrics"]["boundary_payloads_generated"] > 0
    assert report["metrics"]["invalid_payloads_generated"] > 0
    assert report["metrics"]["mutated_payloads_generated"] > 0
    assert report["metrics"]["total_requests"] > 0
    assert report["metrics"]["boundary_payloads_executed"] == 0


def test_mutation_payloads_are_not_executed_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    report = _run_cli(tmp_path, "--include-mutated-payloads", "--max-requests", "1")

    assert len(FakeHttpExecutor.calls) == 1
    assert report["metrics"]["mutated_payloads_generated"] > 0
    assert report["metrics"]["mutated_payloads_executed"] == 0


def test_execute_mutations_without_authorization_flag_fails(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(tmp_path, "--include-mutated-payloads", "--execute-mutations")

    assert exc_info.value.code == 1


def test_execute_mutations_with_authorization_enables_mutation_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    report = _run_cli(
        tmp_path,
        "--include-mutated-payloads",
        "--execute-mutations",
        "--i-understand-mutation-execution-is-authorized",
        "--max-requests",
        "4",
    )

    assert len(FakeHttpExecutor.calls) > 1
    assert report["metrics"]["mutated_payloads_executed"] > 0
    assert report["payload_generation_summary"]["mutation_execution_enabled"] is True


def test_dry_run_prevents_mutation_execution_even_with_execution_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    report = _run_cli(
        tmp_path,
        "--dry-run",
        "--include-mutated-payloads",
        "--execute-mutations",
        "--i-understand-mutation-execution-is-authorized",
    )

    assert FakeHttpExecutor.calls == []
    assert report["metrics"]["mutated_payloads_executed"] == 0


def test_execute_mutations_does_not_imply_execute_attacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    report = _run_cli(
        tmp_path,
        "--include-mutated-payloads",
        "--include-attack-payloads",
        "--execute-mutations",
        "--i-understand-mutation-execution-is-authorized",
        "--max-requests",
        "5",
    )

    assert report["metrics"]["mutated_payloads_executed"] > 0
    assert report["metrics"]["attack_payloads_generated"] > 0
    assert report["metrics"]["attack_payloads_executed"] == 0


def test_execute_attacks_does_not_imply_execute_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    report = _run_cli(
        tmp_path,
        "--include-mutated-payloads",
        "--include-attack-payloads",
        "--execute-attacks",
        "--i-understand-this-is-authorized",
        "--max-requests",
        "3",
    )

    assert report["metrics"]["mutated_payloads_generated"] > 0
    assert report["metrics"]["mutated_payloads_executed"] == 0


def test_mutation_config_flags_are_reflected_in_report(tmp_path: Path) -> None:
    report = _run_cli(
        tmp_path,
        "--dry-run",
        "--include-invalid-payloads",
        "--mutate-sensitive-fields",
        "--allow-invalid-enum-values",
        "--disable-type-confusion",
        "--disable-boundary-values",
        "--disable-null-mutations",
        "--max-mutations-per-payload",
        "2",
        "--max-mutations-per-field",
        "1",
    )
    config = report["payload_generation_summary"]["mutation_config"]

    assert config["include_sensitive_fields"] is True
    assert config["allow_invalid_enum_values"] is True
    assert config["allow_type_confusion"] is False
    assert config["allow_boundary_values"] is False
    assert config["allow_null_mutations"] is False
    assert config["max_mutations_per_payload"] == 2
    assert config["max_mutations_per_field"] == 1


def test_mutation_report_remains_redacted(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(report_path),
            "--dry-run",
            "--include-mutated-payloads",
            "--mutate-sensitive-fields",
        ]
    )
    encoded = report_path.read_text(encoding="utf-8")

    assert "synthetic-auth" not in encoded
    assert "raw-token" not in encoded


def _run_cli(tmp_path: Path, *extra_args: str) -> dict[str, object]:
    report_path = tmp_path / "report.json"
    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(report_path),
            *extra_args,
        ]
    )
    return json.loads(report_path.read_text(encoding="utf-8"))
