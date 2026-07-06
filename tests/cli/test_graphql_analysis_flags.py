import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class GraphQLAnalysisFakeHttpExecutor:
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
        payload_id = str(request_record.payload_id)
        if "payload" in payload_id and request_record.body:
            body = request_record.body if isinstance(request_record.body, dict) else {}
            if "yslfuzz_graphql_sql_marker" in str(body):
                preview = '{"errors":[{"message":"resolver exception database detail"}]}'
            else:
                preview = '{"data":{"search":"ok"}}'
        else:
            preview = '{"data":{"search":"ok"}}'
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview=preview,
            body_hash=preview,
            body_size_bytes=len(preview),
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
        )


def test_cli_safe_marker_attack_generation_works_in_dry_run(tmp_path: Path) -> None:
    report = _run_cli(
        tmp_path,
        "--include-attack-payloads",
        "--attack-category",
        "SQL_INJECTION",
        "--dry-run",
    )

    assert report["graphql_mutation_attack_summary"]["graphql_safe_sql_marker_payloads_generated"] > 0
    assert report["graphql_execution_summary"]["graphql_requests_executed"] == 0


def test_cli_safe_marker_attack_execution_requires_existing_authorization(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(
            tmp_path,
            "--include-attack-payloads",
            "--attack-category",
            "SQL_INJECTION",
            "--execute-attacks",
        )

    assert exc_info.value.code == 1


def test_cli_graphql_analysis_flow_works_with_mock_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLAnalysisFakeHttpExecutor)

    report = _run_cli(
        tmp_path,
        "--include-attack-payloads",
        "--attack-category",
        "SQL_INJECTION",
        "--execute-attacks",
        "--i-understand-this-is-authorized",
        "--graphql-max-requests",
        "20",
    )

    assert report["graphql_analysis_summary"]["graphql_findings_total"] >= 1
    assert report["graphql_analysis_summary"]["graphql_injection_marker_findings"] >= 1


def test_cli_graphql_introspection_probe_requires_explicit_flag(tmp_path: Path) -> None:
    disabled = _run_cli(tmp_path, "--include-attack-payloads", "--dry-run")
    enabled = _run_cli(
        tmp_path,
        "--include-attack-payloads",
        "--attack-category",
        "GRAPHQL_INTROSPECTION_ABUSE",
        "--graphql-include-introspection-probe",
        "--dry-run",
    )

    assert disabled["graphql_mutation_attack_summary"]["graphql_introspection_probe_generated"] is False
    assert enabled["graphql_mutation_attack_summary"]["graphql_introspection_probe_generated"] is True


def _run_cli(tmp_path: Path, *extra_args: str) -> dict[str, Any]:
    output_path = tmp_path / f"report-{len(extra_args)}.json"
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

