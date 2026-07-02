import json

from yslfuzz.models import ScanRun
from yslfuzz.reporting import JsonReporter


def test_report_includes_safe_config_metadata() -> None:
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_config",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        metadata={
            "config_file_used": True,
            "config_profile_name": "local-scan",
            "config_hash": "abc123",
            "config_loaded_at": "2026-07-02T10:00:00+00:00",
            "config_enabled_modes": {"dry_run": True},
        },
    )

    decoded = json.loads(JsonReporter().to_json(report))

    assert decoded["metadata"]["config_file_used"] is True
    assert decoded["metadata"]["config_hash"] == "abc123"
    assert "target:" not in json.dumps(decoded)


def test_report_config_metadata_does_not_include_raw_secrets() -> None:
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_config",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        metadata={
            "config_file_used": True,
            "config_hash": "abc123",
            "note": "token=SENTINEL_CONFIG_VALUE",
        },
    )

    encoded = JsonReporter().to_json(report)

    assert "SENTINEL_CONFIG_VALUE" not in encoded
