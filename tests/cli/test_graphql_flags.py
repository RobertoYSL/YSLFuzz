import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class GraphQLFakeHttpExecutor:
    calls: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: Any,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
    ) -> ExecutionResult:
        self.calls.append(request_record.url)
        return ExecutionResult(
            request_id=request_record.request_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


def test_cli_exposes_graphql_flag_in_scan_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "--graphql-schema" in output
    assert "--graphql-max-selection-depth" in output


def test_cli_rejects_openapi_and_graphql_schema_together(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "scan",
                "--openapi",
                "examples/openapi/simple_users_api.yaml",
                "--graphql-schema",
                "examples/graphql/simple_users_schema.graphql",
                "--base-url",
                "http://localhost:8080",
                "--output",
                str(tmp_path / "report.json"),
            ]
        )

    assert exc_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_cli_can_run_graphql_discovery_path_without_executing_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    GraphQLFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", GraphQLFakeHttpExecutor)
    output_path = tmp_path / "graphql-report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--output",
            str(output_path),
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert GraphQLFakeHttpExecutor.calls == []
    assert report["target_summary"]["api_style"] == "GRAPHQL"
    assert report["metadata"]["graphql_discovery_only"] is False
    assert report["metadata"]["graphql_discovery_summary"]["query_count"] == 2
    assert report["metadata"]["graphql_payload_generation_implemented"] is True
    assert report["metadata"]["graphql_payload_generation"]["graphql_payloads_generated"] == 3
    assert report["metadata"]["graphql_payload_generation"]["execution_enabled"] is False
    assert report["metrics"]["total_requests"] == 0
    assert report["metrics"]["valid_payloads_generated"] == 3


def test_cli_gives_clear_message_that_graphql_execution_is_not_implemented(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--output",
            str(tmp_path / "graphql-report.json"),
        ]
    )

    output = capsys.readouterr().out
    assert "GraphQL discovery and payload generation succeeded" in output
    assert "GraphQL execution is not implemented until Milestone 21" in output


def test_cli_graphql_queries_only_flag_limits_payloads(tmp_path: Path) -> None:
    output_path = tmp_path / "graphql-report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--output",
            str(output_path),
            "--graphql-queries-only",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["metadata"]["graphql_payload_generation"]["graphql_query_payloads_generated"] == 2
    assert report["metadata"]["graphql_payload_generation"]["graphql_mutation_payloads_generated"] == 0
