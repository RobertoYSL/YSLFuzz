# Performance and Stability

YSLFuzz includes scan-level controls to keep scans bounded, reproducible, and easier to
review.

## Scan Limits

Limits can be supplied through CLI flags or config:

- global request budget;
- per-endpoint request budget;
- total payload budget;
- max scan duration;
- GraphQL request budget;
- REST request budget.

Skipped requests are counted for reporting where the execution path can account for them.

## CLI Flags

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --max-requests 50 \
  --max-requests-per-endpoint 10 \
  --max-scan-duration-seconds 60 \
  --rate-limit-rps 2 \
  --min-request-delay-ms 100 \
  --progress \
  --dry-run \
  --output reports/stable_scan.json
```

## Rate Limiting

Rate limiting is disabled by default. When configured, YSLFuzz can enforce approximate
requests-per-second spacing and/or a minimum delay between real HTTP requests. Dry-run skips
execution before rate limiting.

## Retry and Backoff

Retries are disabled by default. When enabled, retry attempts are bounded by `max_retries`
and deterministic backoff settings. Default retry status codes are `429`, `500`, `502`,
`503`, and `504`. Unsafe methods and GraphQL POST retries remain conservative unless
explicitly enabled by lower-level configuration.

## Global Timeout

A max scan duration stops scheduling new requests once the budget is reached. The current
request may finish, remaining work is skipped, and partial metrics can be reported.

## Progress

`--progress` prints concise progress snapshots. Progress output avoids raw payloads and
secrets.

## Reports and Benchmarks

Reports can include scan status, duration, request budget fields, skipped counts, retry
counts, and partial-result status. Benchmark summaries can carry stability fields copied from
scan reports.

## Limitations

- No distributed scanning.
- No persistent resume.
- No advanced adaptive throttling.
- Graceful cancellation is limited to the current CLI scan handling where partial state is available.
