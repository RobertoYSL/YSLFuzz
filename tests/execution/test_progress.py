from yslfuzz.execution import ProgressTracker


def test_progress_tracker_produces_deterministic_snapshot() -> None:
    tracker = ProgressTracker(total_endpoints=2, clock=lambda: 1.0)
    tracker.endpoints_processed = 1
    tracker.total_payloads_generated = 3
    tracker.total_requests_planned = 2
    tracker.requests_executed = 1
    tracker.requests_skipped = 1
    tracker.findings_so_far = 0
    tracker.set_phase("executing")

    snapshot = tracker.snapshot()

    assert snapshot.total_endpoints == 2
    assert snapshot.endpoints_processed == 1
    assert snapshot.current_phase == "executing"
    assert snapshot.elapsed_seconds == 0.0

