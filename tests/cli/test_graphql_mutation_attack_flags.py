import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class GraphQLMutationAttackFakeHttpExecutor:
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
        self.calls.append(str(request_record.payload_id))
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview='{"data":{"ok":true}}',
            body_size_bytes=20,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
        )


def test_cli_graphql_boundary_dry_run_generates_boundary_payloads(tmp_path: Path) -> None:
    report = _run_graphql_cli(
        tmp_path,
        "--include-boundary-payloads",
        "--dry-run",
    )

    assert report["metrics"]["boundary_payloads_generated"] > 0
    assert report["graphql_mutation_attack_summary"]["graphql_boundary_payloads_generated"] > 0
    assert report["graphql_mutation_attack_summary"]["graphql_payloads_skipped_dry_run"] > 0


def test_cli_graphql_invalid_dry_run_generates_invalid_payloads(tmp_path: Path) -> None:
    report = _run_graphql_cli(
        tmp_path,
        "--include-invalid-payloads",
        "--dry-run",
    )

    assert report["metrics"]["invalid_payloads_generated"] > 0
    assert report["graphql_mutation_attack_summary"]["graphql_invalid_payloads_generated"] > 0


def test_cli_graphql_attack_dry_run_generates_attack_payloads_but_executes_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLMutationAttackFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLMutationAttackFakeHttpExecutor)
    report = _run_graphql_cli(tmp_path, "--include-attack-payloads", "--dry-run")

    assert GraphQLMutationAttackFakeHttpExecutor.calls == []
    assert report["metrics"]["attack_payloads_generated"] > 0
    assert report["graphql_execution_summary"]["graphql_requests_executed"] == 0


def test_cli_rejects_graphql_mutation_execution_without_authorization(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_graphql_cli(
            tmp_path,
            "--include-mutated-payloads",
            "--execute-mutations",
        )

    assert exc_info.value.code == 1


def test_cli_rejects_graphql_attack_execution_without_authorization(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_graphql_cli(
            tmp_path,
            "--include-attack-payloads",
            "--execute-attacks",
        )

    assert exc_info.value.code == 1


def test_cli_accepts_graphql_mutation_execution_with_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLMutationAttackFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLMutationAttackFakeHttpExecutor)

    report = _run_graphql_cli(
        tmp_path,
        "--include-mutated-payloads",
        "--execute-mutations",
        "--i-understand-mutation-execution-is-authorized",
        "--graphql-max-requests",
        "20",
    )

    assert GraphQLMutationAttackFakeHttpExecutor.calls
    assert report["graphql_mutation_attack_summary"]["graphql_mutated_payloads_executed"] > 0
    assert report["graphql_mutation_attack_summary"]["graphql_attack_payloads_executed"] == 0


def test_cli_accepts_graphql_attack_execution_with_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLMutationAttackFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLMutationAttackFakeHttpExecutor)

    report = _run_graphql_cli(
        tmp_path,
        "--include-attack-payloads",
        "--execute-attacks",
        "--i-understand-this-is-authorized",
        "--graphql-max-requests",
        "20",
    )

    assert GraphQLMutationAttackFakeHttpExecutor.calls
    assert report["graphql_mutation_attack_summary"]["graphql_attack_payloads_executed"] > 0
    assert report["graphql_mutation_attack_summary"]["graphql_mutated_payloads_executed"] == 0


def test_dry_run_prevents_graphql_non_valid_execution_even_with_execution_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLMutationAttackFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLMutationAttackFakeHttpExecutor)

    report = _run_graphql_cli(
        tmp_path,
        "--include-mutated-payloads",
        "--include-attack-payloads",
        "--execute-mutations",
        "--i-understand-mutation-execution-is-authorized",
        "--execute-attacks",
        "--i-understand-this-is-authorized",
        "--dry-run",
    )

    assert GraphQLMutationAttackFakeHttpExecutor.calls == []
    assert report["graphql_mutation_attack_summary"]["graphql_mutated_payloads_executed"] == 0
    assert report["graphql_mutation_attack_summary"]["graphql_attack_payloads_executed"] == 0


def _run_graphql_cli(tmp_path: Path, *extra_args: str) -> dict[str, Any]:
    output_path = tmp_path / f"graphql-{len(extra_args)}.json"
    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--output",
            str(output_path),
            *extra_args,
        ]
    )
    assert exit_code == 0
    return json.loads(output_path.read_text(encoding="utf-8"))
