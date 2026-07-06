"""Conservative retry and backoff policy."""

from yslfuzz.models.enums import HttpMethod
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord
from yslfuzz.models.stability import RetryConfig


SAFE_RETRY_METHODS = {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}


class BackoffPolicy:
    """Compute deterministic bounded retry delays."""

    def __init__(self, config: RetryConfig | None = None) -> None:
        self.config = config or RetryConfig()

    def delay_for_attempt(self, attempt: int) -> float:
        """Return delay in seconds for a one-based retry attempt."""
        exponent = max(0, attempt - 1)
        delay_ms = self.config.backoff_initial_ms * (self.config.backoff_multiplier ** exponent)
        return min(delay_ms, self.config.backoff_max_ms) / 1000.0


class RetryPolicy:
    """Decide when a request should be retried."""

    def __init__(self, config: RetryConfig | None = None) -> None:
        self.config = config or RetryConfig()

    def should_retry(
        self,
        request: RequestRecord,
        response: ResponseRecord | None,
        result: ExecutionResult,
        attempt: int,
    ) -> bool:
        """Return true when a retry should be attempted."""
        if not self.config.enabled:
            return False
        if attempt >= self.config.max_retries:
            return False
        if not self.config.retry_unsafe_methods and request.method not in SAFE_RETRY_METHODS:
            return False
        if response is not None and response.status_code in self.config.retry_on_status_codes:
            return True
        if result.error_type == "timeout":
            return self.config.retry_on_timeout
        if result.error_type == "connection_error":
            return self.config.retry_on_connection_error
        return False

