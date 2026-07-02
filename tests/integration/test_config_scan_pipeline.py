import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from yslfuzz.models import ExecutionResult, ExecutionStatus, ResponseRecord


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


class ConfigPipelineFakeHttpExecutor:
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
        del timeout_seconds, auth_material
        self.calls.append(request_record.url)
        response = ResponseRecord(
            request_id=request_record.request_id,
            status_code=200,
            body_preview="ok",
            body_hash="hash",
            body_size_bytes=2,
        )
        self.response_records[response.response_id] = response
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response.response_id,
            status=ExecutionStatus.COMPLETED,
            metadata={"scan_run_id": scan_run_id},
        )


def test_config_scan_pipeline_dry_run_prevents_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConfigPipelineFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", ConfigPipelineFakeHttpExecutor)
    config_path = _write_config(tmp_path, dry_run=True)

    CLI_MAIN.main(["scan", "--config", str(config_path)])
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert ConfigPipelineFakeHttpExecutor.calls == []
    assert report["metadata"]["dry_run"] is True
    assert report["metadata"]["config_file_used"] is True


def test_config_scan_pipeline_can_execute_when_explicitly_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConfigPipelineFakeHttpExecutor.calls = []
    monkeypatch.setattr(CLI_MAIN, "HttpExecutor", ConfigPipelineFakeHttpExecutor)
    config_path = _write_config(tmp_path, dry_run=False)

    CLI_MAIN.main(["scan", "--config", str(config_path)])

    assert len(ConfigPipelineFakeHttpExecutor.calls) == 1


def _write_config(tmp_path: Path, *, dry_run: bool) -> Path:
    openapi_path = tmp_path / "openapi.yaml"
    openapi_path.write_text(
        Path("examples/openapi/simple_users_api.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config_path = tmp_path / "scan.json"
    config_path.write_text(
        json.dumps(
            {
                "target": {
                    "openapi_path": "openapi.yaml",
                    "base_url": "http://localhost:8000",
                },
                "execution": {"dry_run": dry_run, "max_requests": 1},
                "reporting": {"output": "report.json"},
            }
        ),
        encoding="utf-8",
    )
    return config_path
