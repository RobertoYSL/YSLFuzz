from yslfuzz.execution import ExecutionBudget
from yslfuzz.models import ApiStyle, PayloadKind, ScanLimits


def test_execution_budget_allows_requests_within_max_requests() -> None:
    budget = ExecutionBudget(ScanLimits(max_requests=1))

    assert budget.allow_request("endpoint_1", PayloadKind.VALID).allowed is True
    budget.record_planned("endpoint_1")


def test_execution_budget_rejects_after_max_requests() -> None:
    budget = ExecutionBudget(ScanLimits(max_requests=1))

    budget.record_planned("endpoint_1")
    decision = budget.allow_request("endpoint_1", PayloadKind.VALID)

    assert decision.allowed is False
    assert decision.reason == "max_requests"
    assert budget.skipped_due_to_max_requests == 1


def test_execution_budget_enforces_max_requests_per_endpoint() -> None:
    budget = ExecutionBudget(ScanLimits(max_requests_per_endpoint=1))

    budget.record_planned("endpoint_1", ApiStyle.REST)
    decision = budget.allow_request("endpoint_1", PayloadKind.VALID, ApiStyle.REST)

    assert decision.allowed is False
    assert decision.reason == "max_requests_per_endpoint"
    assert budget.skipped_due_to_endpoint_budget == 1


def test_execution_budget_tracks_dry_run_and_authorization_skips() -> None:
    budget = ExecutionBudget()

    budget.mark_dry_run_skip(2)
    budget.mark_unauthorized_attack_skip(3)
    budget.mark_unauthorized_mutation_skip(4)

    summary = budget.summary()
    assert summary["requests_skipped_due_to_dry_run"] == 2
    assert summary["requests_skipped_due_to_authorization"] == 7


def test_execution_budget_tracks_timeout_with_fake_clock() -> None:
    now = 0.0

    def clock() -> float:
        return now

    budget = ExecutionBudget(ScanLimits(max_duration_seconds=1), clock=clock, started_at_seconds=0)
    assert budget.timed_out() is False

    now = 2.0
    assert budget.allow_request("endpoint_1", PayloadKind.VALID).reason == "timeout"
    assert budget.summary()["requests_skipped_due_to_timeout"] == 1

