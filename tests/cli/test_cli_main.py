import json
import importlib
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")
CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class FakeHttpExecutor:
    calls: list[str] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: Any,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
    ) -> ExecutionResult:
        self.calls.append(f"{request_record.method.value} {request_record.url}")
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            headers={"Set-Cookie": "session=raw-cookie-secret"},
            cookies={"access_token": "raw-access-token"},
            body_preview="[REDACTED]",
            body_hash="hash",
            body_size_bytes=128,
            response_time_ms=5.0,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


def test_cli_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["--help"])

    assert exc_info.value.code == 0
    assert "YSLFuzz schema-aware API fuzzing MVP" in capsys.readouterr().out


def test_scan_help_works(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    assert exc_info.value.code == 0
    assert "--openapi" in capsys.readouterr().out


def test_scan_command_validates_required_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan"])

    assert exc_info.value.code == 2
    assert "--openapi" in capsys.readouterr().err


def test_scan_command_rejects_missing_openapi_file(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"

    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(
            [
                "scan",
                "--openapi",
                str(tmp_path / "missing.yaml"),
                "--base-url",
                "http://localhost:8000",
                "--output",
                str(output_path),
            ]
        )

    assert exc_info.value.code == 1
    assert not output_path.exists()


def test_scan_command_supports_dry_run_and_does_not_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    output_path = tmp_path / "dry-run-report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(output_path),
            "--dry-run",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert FakeHttpExecutor.calls == []
    assert report["metadata"]["dry_run"] is True
    assert report["metrics"]["payloads_generated"] > 0
    assert report["metrics"]["successful_requests"] == 0


def test_scan_command_writes_json_report_to_temporary_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    output_path = tmp_path / "report.json"

    exit_code = CLI_MAIN.main(
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
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output_path.exists()
    assert report["scan_run_id"].startswith("scan_")
    assert report["metrics"]["total_requests"] == 1
    assert report["metrics"]["successful_requests"] == 1
    assert len(report["request_response_summary"]) == 1


def test_scan_command_respects_max_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(tmp_path / "report.json"),
            "--max-requests",
            "1",
        ]
    )

    assert len(FakeHttpExecutor.calls) == 1


def test_destructive_methods_are_not_executed_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    openapi_path = _write_destructive_openapi(tmp_path)

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(openapi_path),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(tmp_path / "report.json"),
        ]
    )

    assert FakeHttpExecutor.calls == []


def test_allow_destructive_enables_destructive_methods_only_when_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
    openapi_path = _write_destructive_openapi(tmp_path)

    CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(openapi_path),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(tmp_path / "report.json"),
            "--allow-destructive",
        ]
    )

    assert len(FakeHttpExecutor.calls) == 1
    assert FakeHttpExecutor.calls[0].startswith("DELETE ")


def test_output_report_does_not_contain_raw_secret_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)
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
        ]
    )
    encoded = output_path.read_text(encoding="utf-8")

    assert "raw-cookie-secret" not in encoded
    assert "raw-access-token" not in encoded
    assert "Authorization" not in encoded
    assert "raw-password" not in encoded
    assert "raw-api-key" not in encoded
    assert "raw-secret" not in encoded


def test_cli_tests_do_not_use_external_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external network call attempted")

    FakeHttpExecutor.calls = []
    monkeypatch.setattr("socket.create_connection", fail_network_call)
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", FakeHttpExecutor)

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://localhost:8000",
            "--output",
            str(tmp_path / "report.json"),
            "--max-requests",
            "1",
        ]
    )

    assert exit_code == 0


def _write_destructive_openapi(tmp_path: Path) -> Path:
    openapi_path = tmp_path / "destructive.yaml"
    openapi_path.write_text(
        """
openapi: 3.0.3
info:
  title: Destructive API
  version: 1.0.0
servers:
  - url: http://localhost:8000
paths:
  /users/{user_id}:
    delete:
      operationId: deleteUser
      parameters:
        - name: user_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "204":
          description: Deleted
""",
        encoding="utf-8",
    )
    return openapi_path
