"""Lightweight scan progress tracking."""

from time import monotonic
from collections.abc import Callable

from yslfuzz.models.base import utc_now
from yslfuzz.models.stability import ProgressSnapshot


class ProgressTracker:
    """Track coarse scan progress for CLI output and reports."""

    def __init__(
        self,
        *,
        total_endpoints: int = 0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.total_endpoints = total_endpoints
        self.endpoints_processed = 0
        self.total_payloads_generated = 0
        self.total_requests_planned = 0
        self.requests_executed = 0
        self.requests_skipped = 0
        self.findings_so_far = 0
        self.current_phase = "initializing"
        self.started_at = utc_now()
        self._clock = clock or monotonic
        self._started_seconds = self._now()

    def set_phase(self, phase: str) -> None:
        """Set the current progress phase."""
        self.current_phase = phase

    def snapshot(self) -> ProgressSnapshot:
        """Return a deterministic progress snapshot."""
        return ProgressSnapshot(
            total_endpoints=self.total_endpoints,
            endpoints_processed=self.endpoints_processed,
            total_payloads_generated=self.total_payloads_generated,
            total_requests_planned=self.total_requests_planned,
            requests_executed=self.requests_executed,
            requests_skipped=self.requests_skipped,
            findings_so_far=self.findings_so_far,
            current_phase=self.current_phase,
            started_at=self.started_at,
            elapsed_seconds=round(self._now() - self._started_seconds, 6),
        )

    def _now(self) -> float:
        return float(self._clock())
