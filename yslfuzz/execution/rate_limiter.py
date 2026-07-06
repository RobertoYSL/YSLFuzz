"""Deterministic request rate limiter."""

from time import monotonic, sleep
from collections.abc import Callable

from yslfuzz.models.stability import RateLimitConfig


class RateLimiter:
    """Apply configured spacing before HTTP requests."""

    def __init__(
        self,
        config: RateLimitConfig | None = None,
        *,
        sleeper: Callable[[float], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config or RateLimitConfig()
        self._sleeper = sleeper or sleep
        self._clock = clock or monotonic
        self._last_request_at: float | None = None

    def wait(self) -> None:
        """Sleep until the next request is allowed."""
        delay = self._delay_seconds()
        if delay > 0:
            self._sleep(delay)
        self._last_request_at = self._now()

    def _delay_seconds(self) -> float:
        if self._last_request_at is None:
            return 0.0
        delays: list[float] = []
        if self.config.min_delay_ms is not None:
            delays.append(self.config.min_delay_ms / 1000.0)
        if self.config.requests_per_second is not None:
            delays.append(1.0 / self.config.requests_per_second)
        if not delays:
            return 0.0
        elapsed = self._now() - self._last_request_at
        return max(0.0, max(delays) - elapsed)

    def _now(self) -> float:
        return float(self._clock())

    def _sleep(self, seconds: float) -> None:
        self._sleeper(seconds)
