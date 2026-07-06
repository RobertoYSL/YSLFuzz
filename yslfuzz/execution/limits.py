"""Execution budget and scan limit helpers."""

from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic
from collections.abc import Callable

from yslfuzz.models.base import utc_now
from yslfuzz.models.enums import ApiStyle, PayloadKind
from yslfuzz.models.stability import ScanLimits


@dataclass(frozen=True)
class BudgetDecision:
    """Decision returned by ExecutionBudget."""

    allowed: bool
    reason: str | None = None


@dataclass
class ExecutionBudget:
    """Central request budget accounting for scan execution."""

    limits: ScanLimits = field(default_factory=ScanLimits)
    clock: Callable[[], float] | None = None
    started_at: datetime = field(default_factory=utc_now)
    started_at_seconds: float | None = None
    planned_requests: int = 0
    executed_requests: int = 0
    skipped_requests: int = 0
    skipped_due_to_dry_run: int = 0
    skipped_due_to_max_requests: int = 0
    skipped_due_to_endpoint_budget: int = 0
    skipped_due_to_unauthorized_mutation: int = 0
    skipped_due_to_unauthorized_attack: int = 0
    skipped_due_to_timeout: int = 0
    skipped_due_to_cancellation: int = 0
    total_retries_attempted: int = 0
    _planned_by_endpoint: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.started_at_seconds is None:
            self.started_at_seconds = self._now()

    def allow_request(
        self,
        endpoint_id: str,
        payload_kind: PayloadKind,
        api_style: ApiStyle = ApiStyle.REST,
    ) -> BudgetDecision:
        """Return whether another request can be planned."""
        del payload_kind
        if self.timed_out():
            self.mark_timeout_skip()
            return BudgetDecision(False, "timeout")
        if self.limits.max_requests is not None and self.planned_requests >= self.limits.max_requests:
            self.skipped_requests += 1
            self.skipped_due_to_max_requests += 1
            return BudgetDecision(False, "max_requests")
        if api_style == ApiStyle.GRAPHQL and self.limits.max_graphql_requests is not None:
            graphql_planned = sum(
                count
                for key, count in self._planned_by_endpoint.items()
                if key.startswith("GRAPHQL:")
            )
            if graphql_planned >= self.limits.max_graphql_requests:
                self.skipped_requests += 1
                self.skipped_due_to_max_requests += 1
                return BudgetDecision(False, "max_graphql_requests")
        if api_style == ApiStyle.REST and self.limits.max_rest_requests is not None:
            rest_planned = sum(
                count for key, count in self._planned_by_endpoint.items() if key.startswith("REST:")
            )
            if rest_planned >= self.limits.max_rest_requests:
                self.skipped_requests += 1
                self.skipped_due_to_max_requests += 1
                return BudgetDecision(False, "max_rest_requests")
        endpoint_key = f"{api_style.value}:{endpoint_id}"
        if (
            self.limits.max_requests_per_endpoint is not None
            and self._planned_by_endpoint.get(endpoint_key, 0)
            >= self.limits.max_requests_per_endpoint
        ):
            self.skipped_requests += 1
            self.skipped_due_to_endpoint_budget += 1
            return BudgetDecision(False, "max_requests_per_endpoint")
        return BudgetDecision(True)

    def record_planned(self, endpoint_id: str, api_style: ApiStyle = ApiStyle.REST) -> None:
        """Record a planned request."""
        endpoint_key = f"{api_style.value}:{endpoint_id}"
        self.planned_requests += 1
        self._planned_by_endpoint[endpoint_key] = self._planned_by_endpoint.get(endpoint_key, 0) + 1

    def record_executed(self) -> None:
        """Record one executed request."""
        self.executed_requests += 1

    def mark_dry_run_skip(self, count: int = 1) -> None:
        """Record dry-run skipped execution."""
        self.skipped_requests += count
        self.skipped_due_to_dry_run += count

    def mark_unauthorized_mutation_skip(self, count: int = 1) -> None:
        """Record mutation payloads skipped by authorization gates."""
        self.skipped_requests += count
        self.skipped_due_to_unauthorized_mutation += count

    def mark_unauthorized_attack_skip(self, count: int = 1) -> None:
        """Record attack payloads skipped by authorization gates."""
        self.skipped_requests += count
        self.skipped_due_to_unauthorized_attack += count

    def mark_timeout_skip(self, count: int = 1) -> None:
        """Record timeout skipped scheduling."""
        self.skipped_requests += count
        self.skipped_due_to_timeout += count

    def record_retries(self, count: int) -> None:
        """Record retry attempts."""
        self.total_retries_attempted += count

    def timed_out(self) -> bool:
        """Return true when max scan duration has elapsed."""
        if self.limits.max_duration_seconds is None:
            return False
        assert self.started_at_seconds is not None
        return self._now() - self.started_at_seconds >= self.limits.max_duration_seconds

    def summary(self) -> dict[str, object]:
        """Return report-safe budget counters."""
        return {
            "planned_requests": self.planned_requests,
            "executed_requests": self.executed_requests,
            "skipped_requests": self.skipped_requests,
            "requests_skipped_due_to_budget": self.skipped_due_to_max_requests,
            "requests_skipped_due_to_endpoint_budget": self.skipped_due_to_endpoint_budget,
            "requests_skipped_due_to_timeout": self.skipped_due_to_timeout,
            "requests_skipped_due_to_dry_run": self.skipped_due_to_dry_run,
            "requests_skipped_due_to_authorization": (
                self.skipped_due_to_unauthorized_mutation
                + self.skipped_due_to_unauthorized_attack
            ),
            "requests_skipped_due_to_unauthorized_mutation": (
                self.skipped_due_to_unauthorized_mutation
            ),
            "requests_skipped_due_to_unauthorized_attack": self.skipped_due_to_unauthorized_attack,
            "requests_skipped_due_to_cancellation": self.skipped_due_to_cancellation,
            "total_retries_attempted": self.total_retries_attempted,
            "timed_out": self.timed_out() or self.skipped_due_to_timeout > 0,
        }

    def _now(self) -> float:
        if self.clock is None:
            return monotonic()
        return float(self.clock())
