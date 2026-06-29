"""HTTP execution using httpx with YSLFuzz execution records."""

from hashlib import sha256
from time import perf_counter

import httpx

from yslfuzz.execution.errors import ExecutionError
from yslfuzz.execution.redaction import redact_mapping_values
from yslfuzz.models.base import REDACTED_VALUE
from yslfuzz.models.enums import ExecutionStatus
from yslfuzz.models.execution import ExecutionResult, RequestRecord, ResponseRecord


class HttpExecutor:
    """Execute request records with httpx and capture response records."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client
        self.response_records: dict[str, ResponseRecord] = {}

    def execute(
        self,
        request_record: RequestRecord,
        scan_run_id: str,
        timeout_seconds: float = 10.0,
    ) -> ExecutionResult:
        """Execute a request record and return the execution result."""
        started = perf_counter()
        try:
            response = self._send(request_record, timeout_seconds)
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
            metadata={"scan_run_id": scan_run_id},
        )

    def _send(self, request_record: RequestRecord, timeout_seconds: float) -> httpx.Response:
        client = self._client
        headers = self._headers_for_send(request_record)
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

    def _headers_for_send(self, request_record: RequestRecord) -> dict[str, str]:
        headers = {str(key): str(value) for key, value in request_record.headers.items()}
        if request_record.cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(
                f"{name}={REDACTED_VALUE}" for name in request_record.cookies
            )
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

    def _body_preview(self, body: bytes) -> str | None:
        if not body:
            return None
        preview = body[:1024].decode("utf-8", errors="replace")
        for marker in ("authorization", "api_key", "apikey", "jwt", "password", "secret", "token"):
            if marker in preview.lower():
                return "[REDACTED]"
        return preview
