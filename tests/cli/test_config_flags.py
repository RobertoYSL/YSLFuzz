import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class ConfigFakeHttpExecutor:
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
        self.calls.append(
            {
                "url": request_record.url,
                "timeout_seconds": timeout_seconds,
                "sent_headers": sent_headers,
            }
        )
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
            metadata={"scan_run_id": scan_run_id},
        )


def test_scan_help_exposes_config_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        CLI_MAIN.main(["scan", "--help"])

    assert exc_info.value.code == 0
    assert "--config" in capsys.readouterr().out


def test_cli_scan_works_with_simple_users_dry_run_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConfigFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", ConfigFakeHttpExecutor)
    config_path = _write_config(tmp_path)

    exit_code = CLI_MAIN.main(["scan", "--config", str(config_path)])
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert ConfigFakeHttpExecutor.calls == []
    assert report["metadata"]["config_file_used"] is True
    assert report["metadata"]["config_hash"]


def test_cli_flags_override_config_output_path(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    override_output = tmp_path / "override.json"

    CLI_MAIN.main(["scan", "--config", str(config_path), "--output", str(override_output)])

    assert override_output.exists()
    assert not (tmp_path / "report.json").exists()


def test_cli_dry_run_overrides_config_execution_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConfigFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", ConfigFakeHttpExecutor)
    config_path = _write_config(tmp_path, execution={"dry_run": False, "max_requests": 1})

    CLI_MAIN.main(["scan", "--config", str(config_path), "--dry-run"])

    assert ConfigFakeHttpExecutor.calls == []


def test_cli_flags_override_config_payload_include_modes(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)

    CLI_MAIN.main(["scan", "--config", str(config_path), "--include-boundary-payloads"])
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert report["metrics"]["boundary_payloads_generated"] > 0


def test_cli_auth_flags_override_config_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YSLFUZZ_TOKEN", "SENTINEL_BEARER")
    monkeypatch.setenv("YSLFUZZ_API_KEY", "SENTINEL_API")
    ConfigFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", ConfigFakeHttpExecutor)
    config_path = _write_config(
        tmp_path,
        auth={"bearer_env": "YSLFUZZ_TOKEN"},
        execution={"dry_run": False, "max_requests": 1},
    )

    CLI_MAIN.main(
        [
            "scan",
            "--config",
            str(config_path),
            "--auth-api-key-env",
            "YSLFUZZ_API_KEY",
        ]
    )
    report_text = (tmp_path / "report.json").read_text(encoding="utf-8")

    assert ConfigFakeHttpExecutor.calls[0]["sent_headers"]["X-API-Key"] == "SENTINEL_API"
    assert "SENTINEL_API" not in report_text
    assert "SENTINEL_BEARER" not in report_text


def _write_config(
    tmp_path: Path,
    *,
    auth: dict[str, object] | None = None,
    execution: dict[str, object] | None = None,
) -> Path:
    openapi_path = tmp_path / "openapi.yaml"
    openapi_path.write_text(
        Path("examples/openapi/simple_users_api.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    data: dict[str, object] = {
        "target": {
            "openapi_path": "openapi.yaml",
            "base_url": "http://localhost:8000",
            "target_name": "simple-users",
        },
        "execution": execution or {"dry_run": True, "max_requests": 1},
        "reporting": {"output": "report.json"},
        "metadata": {"scan_name": "config-test"},
    }
    if auth is not None:
        data["auth"] = auth
    config_path = tmp_path / "scan.json"
    config_path.write_text(json.dumps(data), encoding="utf-8")
    return config_path
