from yslfuzz.models import ScanRun
from yslfuzz.reporting import JsonReporter


def test_report_includes_stability_summary() -> None:
    stability = {
        "scan_status": "completed",
        "max_requests": 10,
        "max_requests_per_endpoint": 2,
        "total_retries_attempted": 1,
        "requests_skipped_due_to_budget": 3,
        "timed_out": False,
    }

    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        metadata={"stability": stability},
    )
    decoded = JsonReporter().to_dict(report)

    assert decoded["stability_summary"] == stability

