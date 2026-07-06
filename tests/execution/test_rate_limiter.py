from yslfuzz.execution import RateLimiter
from yslfuzz.models import RateLimitConfig


def test_rate_limiter_noop_without_config() -> None:
    sleeps: list[float] = []
    limiter = RateLimiter(RateLimitConfig(), sleeper=sleeps.append, clock=lambda: 0.0)

    limiter.wait()
    limiter.wait()

    assert sleeps == []


def test_rate_limiter_enforces_min_delay_with_fake_sleeper() -> None:
    now = 0.0
    sleeps: list[float] = []

    def clock() -> float:
        return now

    limiter = RateLimiter(RateLimitConfig(min_delay_ms=100), sleeper=sleeps.append, clock=clock)
    limiter.wait()
    limiter.wait()

    assert sleeps == [0.1]


def test_rate_limiter_enforces_rps_with_fake_clock() -> None:
    now = 0.0
    sleeps: list[float] = []

    def clock() -> float:
        return now

    limiter = RateLimiter(
        RateLimitConfig(requests_per_second=2.0),
        sleeper=sleeps.append,
        clock=clock,
    )
    limiter.wait()
    limiter.wait()

    assert sleeps == [0.5]

