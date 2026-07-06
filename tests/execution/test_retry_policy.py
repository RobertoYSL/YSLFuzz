from yslfuzz.execution import BackoffPolicy, RetryPolicy
from yslfuzz.models import ExecutionResult, ExecutionStatus, HttpMethod, RequestRecord, ResponseRecord, RetryConfig


def test_retry_policy_disabled_by_default() -> None:
    request = _request(HttpMethod.GET)
    result = ExecutionResult(request_id=request.request_id, status=ExecutionStatus.COMPLETED)

    assert RetryPolicy().should_retry(request, None, result, 0) is False


def test_retry_policy_retries_configured_status_codes_when_enabled() -> None:
    request = _request(HttpMethod.GET)
    response = ResponseRecord(request_id=request.request_id, status_code=503)
    result = ExecutionResult(
        request_id=request.request_id,
        response_id=response.response_id,
        status=ExecutionStatus.COMPLETED,
    )

    assert RetryPolicy(RetryConfig(enabled=True, max_retries=1)).should_retry(
        request,
        response,
        result,
        0,
    )


def test_retry_policy_respects_status_and_max_retries_and_method_safety() -> None:
    get_request = _request(HttpMethod.GET)
    post_request = _request(HttpMethod.POST)
    response = ResponseRecord(request_id=get_request.request_id, status_code=400)
    retry_response = ResponseRecord(request_id=get_request.request_id, status_code=503)
    result = ExecutionResult(request_id=get_request.request_id, status=ExecutionStatus.COMPLETED)
    policy = RetryPolicy(RetryConfig(enabled=True, max_retries=1))

    assert policy.should_retry(get_request, response, result, 0) is False
    assert policy.should_retry(get_request, retry_response, result, 1) is False
    assert policy.should_retry(post_request, retry_response, result, 0) is False


def test_backoff_policy_computes_deterministic_bounded_delays() -> None:
    policy = BackoffPolicy(
        RetryConfig(
            enabled=True,
            max_retries=3,
            backoff_initial_ms=100,
            backoff_multiplier=2.0,
            backoff_max_ms=250,
        )
    )

    assert policy.delay_for_attempt(1) == 0.1
    assert policy.delay_for_attempt(2) == 0.2
    assert policy.delay_for_attempt(3) == 0.25


def _request(method: HttpMethod) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{method.value}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        method=method,
        url="http://localhost:8080/users",
    )

