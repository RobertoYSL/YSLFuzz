"""HTTP execution using httpx with YSLFuzz execution records."""

from hashlib import sha256
from time import perf_counter
from collections.abc import Callable

import httpx

from yslfuzz.execution.errors import ExecutionError
from yslfuzz.execution.redaction import redact_mapping_values
from yslfuzz.execution.rate_limiter import RateLimiter
from yslfuzz.execution.retry import BackoffPolicy, RetryPolicy
from yslfuzz.models.auth import ResolvedAuthMaterial
from yslfuzz.models.base import REDACTED_VALUE
from yslfuzz.models.enums import ExecutionStatus
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord


class HttpExecutor:
    """Execute request records with httpx and capture response records."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        rate_limiter: RateLimiter | None = None,
        retry_policy: RetryPolicy | None = None,
        backoff_policy: BackoffPolicy | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._client = client
        self._rate_limiter = rate_limiter
        self._retry_policy = retry_policy or RetryPolicy()
        self._backoff_policy = backoff_policy or BackoffPolicy(self._retry_policy.config)
        self._sleeper = sleeper
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: RequestRecord,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
        auth_material: ResolvedAuthMaterial | None = None,
    ) -> ExecutionResult:
        """Execute a request record and return the execution result."""
        attempt = 0
        retries_attempted = 0
        last_result: ExecutionResult | None = None
        while True:
            if self._rate_limiter is not None:
                self._rate_limiter.wait()
            result = self._execute_once(
                request_record,
                scan_run_id=scan_run_id,
                timeout_seconds=timeout_seconds,
                auth_material=auth_material,
                retry_count=retries_attempted,
            )
            response = self.response_records.get(result.response_id) if result.response_id else None
            last_result = result
            if not self._retry_policy.should_retry(request_record, response, result, attempt):
                result.retry_count = retries_attempted
                result.metadata["total_retries_attempted"] = retries_attempted
                if response is not None:
                    response.metadata["retry_count"] = retries_attempted
                return result
            attempt += 1
            retries_attempted += 1
            self._sleep(self._backoff_policy.delay_for_attempt(retries_attempted))
        return last_result

    def _execute_once(
        self,
        request_record: RequestRecord,
        *,
        scan_run_id: str,
        timeout_seconds: float,
        auth_material: ResolvedAuthMaterial | None,
        retry_count: int,
    ) -> ExecutionResult:
        """Execute one HTTP attempt."""
        started = perf_counter()
        try:
            response = self._send(request_record, timeout_seconds, auth_material)
        except httpx.TimeoutException as exc:
            return self._failed_result(request_record, "timeout", str(exc))
        except httpx.ConnectError as exc:
            return self._failed_result(request_record, "connection_error", str(exc))
        except httpx.InvalidURL as exc:
            return self._failed_result(request_record, "invalid_url", str(exc))
        except httpx.HTTPError as exc:
            return self._failed_result(request_record, "http_error", str(exc))
        except ExecutionError as exc:
            return self._failed_result(request_record, exc.__class__.__name__, str(exc))

        response_record = self._response_record(request_record, response, started)
        self.response_records[response_record.response_id] = response_record
        return ExecutionResult(
            request_id=request_record.request_id,
            response_id=response_record.response_id,
            status=ExecutionStatus.COMPLETED,
            retry_count=retry_count,
            metadata={"scan_run_id": scan_run_id, "retry_count": retry_count},
        )

    def _send(
        self,
        request_record: RequestRecord,
        timeout_seconds: float,
        auth_material: ResolvedAuthMaterial | None = None,
    ) -> httpx.Response:
        client = self._client
        headers = self._headers_for_send(request_record, auth_material)
        if client is not None:
            return client.request(
                request_record.method.value,
                request_record.url,
                params=request_record.query_params,
                headers=headers,
                json=request_record.body if isinstance(request_record.body, dict) else None,
                content=request_record.body if isinstance(request_record.body, str) else None,
                timeout=timeout_seconds,
            )

        with httpx.Client() as owned_client:
            return owned_client.request(
                request_record.method.value,
                request_record.url,
                params=request_record.query_params,
                headers=headers,
                json=request_record.body if isinstance(request_record.body, dict) else None,
                content=request_record.body if isinstance(request_record.body, str) else None,
                timeout=timeout_seconds,
            )

    def _headers_for_send(
        self,
        request_record: RequestRecord,
        auth_material: ResolvedAuthMaterial | None = None,
    ) -> dict[str, str]:
        headers = {str(key): str(value) for key, value in request_record.headers.items()}
        if request_record.cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(
                f"{name}={REDACTED_VALUE}" for name in request_record.cookies
            )
        if auth_material is not None:
            headers.update(auth_material.headers_for_send())
        return headers

    def _response_record(
        self,
        request_record: RequestRecord,
        response: httpx.Response,
        started: float,
    ) -> ResponseRecord:
        body = response.content
        return ResponseRecord(
            request_id=request_record.request_id,
            status_code=response.status_code,
            headers=redact_mapping_values(dict(response.headers)),
            cookies=redact_mapping_values(dict(response.cookies)),
            body_preview=self._body_preview(body),
            body_hash=sha256(body).hexdigest() if body else None,
            body_size_bytes=len(body),
            response_time_ms=round((perf_counter() - started) * 1000, 3),
        )

    def _failed_result(
        self,
        request_record: RequestRecord,
        error_type: str,
        error_message: str,
    ) -> ExecutionResult:
        return ExecutionResult(
            request_id=request_record.request_id,
            status=ExecutionStatus.FAILED,
            error_type=error_type,
            error_message=error_message,
        )

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if self._sleeper is not None:
            self._sleeper(seconds)
            return
        from time import sleep

        sleep(seconds)

    def _body_preview(self, body: bytes) -> str | None:
        if not body:
            return None
        preview = body[:1024].decode("utf-8", errors="replace")
        for marker in ("authorization", "api_key", "apikey", "jwt", "password", "secret", "token"):
            if marker in preview.lower():
                return "[REDACTED]"
        return preview
