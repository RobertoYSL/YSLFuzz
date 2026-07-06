from yslfuzz.execution import ExecutionBudget
from yslfuzz.models import PayloadKind, ScanLimits, ScanRun
from yslfuzz.reporting import JsonReporter


def test_global_timeout_stops_scheduling_and_marks_skips() -> None:
    now = 2.0
    budget = ExecutionBudget(
        ScanLimits(max_duration_seconds=1),
        clock=lambda: now,
        started_at_seconds=0,
    )

    decision = budget.allow_request("endpoint_1", PayloadKind.VALID)

    assert decision.allowed is False
    assert decision.reason == "timeout"
    assert budget.summary()["timed_out"] is True


def test_global_timeout_allows_partial_report_creation() -> None:
    budget = ExecutionBudget(ScanLimits(max_duration_seconds=0), clock=lambda: 1.0, started_at_seconds=0)
    budget.mark_timeout_skip()
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        metadata={"stability": {"scan_status": "timed_out", **budget.summary()}},
    )

    decoded = JsonReporter().to_dict(report)
    assert decoded["stability_summary"]["scan_status"] == "timed_out"
    assert decoded["stability_summary"]["timed_out"] is True

