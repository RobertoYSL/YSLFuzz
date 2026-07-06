import json

from yslfuzz.models import ScanRun
from yslfuzz.reporting import JsonReporter


def test_report_includes_graphql_execution_summary() -> None:
    summary = {
        "api_style": "graphql",
        "graphql_schema_id": "graphql_schema_1",
        "graphql_endpoint_path": "/graphql",
        "graphql_requests_planned": 2,
        "graphql_requests_executed": 2,
        "graphql_requests_skipped_dry_run": 0,
        "graphql_responses_received": 2,
        "graphql_errors_transport": 0,
        "graphql_errors_application": 1,
        "execution_enabled": True,
        "dry_run": False,
    }

    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        metadata={"graphql_execution": summary},
    )
    decoded = JsonReporter().to_dict(report)

    assert decoded["graphql_execution_summary"] == summary
    assert decoded["payload_generation_summary"]["graphql_execution"] == summary


def test_report_does_not_include_raw_graphql_auth_value() -> None:
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        metadata={
            "graphql_execution": {
                "api_style": "graphql",
                "graphql_endpoint_path": "/graphql",
                "note": "no raw fake-token value",
            }
        },
    )

    assert "raw-secret-token" not in json.dumps(JsonReporter().to_dict(report))
