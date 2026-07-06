import httpx

from yslfuzz.execution import BackoffPolicy, HttpExecutor, RateLimiter, RetryPolicy
from yslfuzz.models import ExecutionStatus, HttpMethod, RateLimitConfig, RequestRecord, RetryConfig


def test_http_executor_applies_retry_policy_against_mock_transport() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503 if calls == 1 else 200, json={"ok": True})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler)),
        retry_policy=RetryPolicy(RetryConfig(enabled=True, max_retries=1)),
        backoff_policy=BackoffPolicy(RetryConfig(enabled=True, max_retries=1, backoff_initial_ms=0)),
        sleeper=lambda seconds: None,
    )
    result = executor.execute(_request(HttpMethod.GET), scan_run_id="scan_1")

    assert result.status == ExecutionStatus.COMPLETED
    assert result.retry_count == 1
    assert calls == 2


def test_http_executor_applies_rate_limiter_without_slow_sleep() -> None:
    sleeps: list[float] = []
    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
        rate_limiter=RateLimiter(RateLimitConfig(min_delay_ms=100), sleeper=sleeps.append, clock=lambda: 0.0),
    )

    executor.execute(_request(HttpMethod.GET), scan_run_id="scan_1")
    executor.execute(_request(HttpMethod.GET), scan_run_id="scan_1")

    assert sleeps == [0.1]


def _request(method: HttpMethod) -> RequestRecord:
    return RequestRecord(
        request_id="request_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        method=method,
        url="http://localhost:8080/users",
    )

