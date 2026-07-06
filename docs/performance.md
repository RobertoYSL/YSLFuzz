# Performance, Rate Limiting, and Scan Stability

YSLFuzz includes bounded scan controls for predictable local and authorized scans. These controls do
not add attack behavior. They limit scheduling, pace HTTP execution, and report skipped work.

## Request Budgets

Scan limits are configured through CLI flags or config profiles:

- `max_requests`: global request cap.
- `max_requests_per_endpoint`: per-endpoint request cap.
- `max_duration_seconds`: global scheduling timeout.
- `max_graphql_requests`: GraphQL-specific request cap.
- `max_rest_requests`: REST-specific request cap.

Budgets are checked before scheduling where possible. Skipped requests are counted in report
metadata.

## Rate Limiting

Rate limiting is disabled by default.

CLI flags:

```bash
--rate-limit-rps 2.0
--min-request-delay-ms 100
```

When enabled, the synchronous executor waits before real HTTP requests. Dry-run does not execute
HTTP requests and therefore does not need pacing.

## Retry and Backoff

Retries are disabled by default.

CLI flags:

```bash
--retry
--max-retries 2
--retry-status-code 429
--retry-status-code 503
--backoff-initial-ms 100
--backoff-max-ms 1000
```

Retry behavior is conservative:

- bounded retry count;
- no jitter by default;
- deterministic exponential backoff;
- default retry status codes: `429`, `500`, `502`, `503`, `504`;
- unsafe methods and GraphQL POST requests are not retried by default.

## Global Timeout

`--max-scan-duration-seconds` stops scheduling new requests after the configured duration. YSLFuzz
writes a partial report with `scan_status: timed_out` when timeout accounting is reached.

## Progress

`--progress` prints concise progress snapshots. Progress output contains counts only and does not
print payload bodies, credentials, headers, cookies, tokens, or response bodies.

## Reporting

Reports include `stability_summary` with fields such as:

- `scan_status`
- `max_requests`
- `max_requests_per_endpoint`
- `max_duration_seconds`
- `rate_limit_rps`
- `min_request_delay_ms`
- `retry_enabled`
- `max_retries`
- `total_retries_attempted`
- `requests_skipped_due_to_budget`
- `requests_skipped_due_to_endpoint_budget`
- `requests_skipped_due_to_timeout`
- `requests_skipped_due_to_dry_run`
- `requests_skipped_due_to_authorization`
- `duration_seconds`
- `partial_results`

Benchmark job summaries include selected stability fields when the scan report contains them.

## Config Example

```yaml
limits:
  max_requests: 100
  max_requests_per_endpoint: 10
  max_duration_seconds: 60
  max_graphql_requests: 50
  max_rest_requests: 50

stability:
  rate_limit_rps: 2.0
  min_request_delay_ms: 100
  progress: true
  retry:
    enabled: true
    max_retries: 2
    retry_on_status_codes: [429, 500, 502, 503, 504]
    backoff_initial_ms: 100
    backoff_multiplier: 2.0
    backoff_max_ms: 1000
```

## Safety Notes

- Dry-run still prevents all HTTP execution.
- Scope validation remains active.
- Destructive method blocking remains active.
- Mutation and attack execution still require explicit authorization.
- Auth redaction remains active.
- No external services are used for throttling or retry.

## Limitations

- No distributed scanning.
- No async rewrite.
- No adaptive throttling.
- No persistent resume.
- KeyboardInterrupt partial-report cancellation is not implemented in this milestone.

