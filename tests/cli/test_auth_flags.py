import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")
CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class AuthAwareFakeHttpExecutor:
    calls: list[dict[str, Any]] = []

    def __init__(self) -> None:
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: Any,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
        auth_material: Any = None,
    ) -> ExecutionResult:
        sent_headers = auth_material.headers_for_send() if auth_material is not None else {}
        self.calls.append({"request": request_record, "sent_headers": sent_headers})
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview="ok",
            body_hash="hash",
            body_size_bytes=2,
            response_time_ms=1.0,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id, "timeout_seconds": timeout_seconds},
        )


def test_scan_help_exposes_auth_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--auth-bearer-env" in output
    assert "--auth-api-key-env" in output
    assert "--auth-cookie-env" in output
    assert "--auth-header" in output


def test_cli_rejects_raw_auth_token_usage(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
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
                "--auth-bearer-env",
                "eyJhbGciOi.fake.jwt",
            ]
        )

    assert exc_info.value.code == 1
    assert "raw credential values" in capsys.readouterr().err


def test_cli_builds_bearer_auth_profile_from_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_BEARER")
    report, calls = _run_auth_scan(
        tmp_path,
        monkeypatch,
        ["--auth-bearer-env", "YSLFUZZ_TOKEN"],
    )

    assert calls[0]["sent_headers"]["Authorization"] == "Bearer SENTINEL_BEARER"
    assert report["metadata"]["authentication_enabled"] is True
    assert report["metadata"]["authentication_types"] == ["bearer"]
    assert "SENTINEL_BEARER" not in json.dumps(report)


def test_cli_builds_api_key_auth_profile_from_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_API_KEY", "SENTINEL_API")
    report, calls = _run_auth_scan(
        tmp_path,
        monkeypatch,
        [
            "--auth-api-key-env",
            "YSLFUZZ_API_KEY",
            "--auth-api-key-header",
            "X-API-Key",
        ],
    )

    assert calls[0]["sent_headers"]["X-API-Key"] == "SENTINEL_API"
    assert "SENTINEL_API" not in json.dumps(report)


def test_cli_builds_cookie_auth_profile_from_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_SESSION", "SENTINEL_SESSION")
    report, calls = _run_auth_scan(
        tmp_path,
        monkeypatch,
        [
            "--auth-cookie-env",
            "YSLFUZZ_SESSION",
            "--auth-cookie-name",
            "session",
        ],
    )

    assert calls[0]["sent_headers"]["Cookie"] == "session=SENTINEL_SESSION"
    assert "SENTINEL_SESSION" not in json.dumps(report)


def test_cli_builds_custom_header_auth_profile_from_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_CUSTOM_AUTH", "SENTINEL_CUSTOM")
    report, calls = _run_auth_scan(
        tmp_path,
        monkeypatch,
        ["--auth-header", "X-Custom-Auth:YSLFUZZ_CUSTOM_AUTH"],
    )

    assert calls[0]["sent_headers"]["X-Custom-Auth"] == "SENTINEL_CUSTOM"
    assert report["metadata"]["authentication_types"] == ["custom_header"]
    assert "SENTINEL_CUSTOM" not in json.dumps(report)


def test_cli_fails_clearly_on_missing_required_auth_environment_variable(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("YSLFUZZ_TOKEN", raising=False)

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
                "--auth-bearer-env",
                "YSLFUZZ_TOKEN",
            ]
        )

    error = capsys.readouterr().err
    assert exc_info.value.code == 1
    assert "environment variable is not set" in error
    assert "YSLFUZZ_TOKEN" not in error


def test_cli_dry_run_does_not_execute_authenticated_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_BEARER")
    AuthAwareFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", AuthAwareFakeHttpExecutor)
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
            "--dry-run",
            "--max-requests",
            "1",
            "--auth-bearer-env",
            "YSLFUZZ_TOKEN",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert AuthAwareFakeHttpExecutor.calls == []
    assert report["metadata"]["authentication_enabled"] is True
    assert "SENTINEL_BEARER" not in json.dumps(report)


def _run_auth_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    auth_args: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    AuthAwareFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", AuthAwareFakeHttpExecutor)
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
            *auth_args,
        ]
    )

    assert exit_code == 0
    return json.loads(output_path.read_text(encoding="utf-8")), AuthAwareFakeHttpExecutor.calls
