# CLI Reference

Use `uv run yslfuzz --help` from the repository root to view current help text.

## Top-Level Commands

```bash
uv run yslfuzz --help
```

Commands:

- `scan`: run a REST/OpenAPI or GraphQL scan.
- `evaluate`: compare a JSON scan report to ground truth.
- `benchmark`: run benchmark jobs from a benchmark config.
- `labs`: list or inspect local lab packs.

## scan

Target inputs:

- `--config PATH`: load a JSON/YAML scan configuration profile.
- `--openapi PATH`: local OpenAPI YAML/JSON file.
- `--graphql-schema PATH`: local GraphQL SDL or local introspection JSON file.
- `--base-url URL`: target base URL.
- `--output PATH`: JSON report path.

`--openapi` and `--graphql-schema` are mutually exclusive.

General execution:

- `--max-requests INT`
- `--timeout FLOAT`
- `--allow-destructive`
- `--dry-run`
- `--verbose`

Payload modes:

- `--include-boundary-payloads`
- `--include-invalid-payloads`
- `--include-mutated-payloads`
- `--include-attack-payloads`
- `--attack-category CATEGORY`
- `--max-mutations-per-payload INT`
- `--max-mutations-per-field INT`
- `--max-attack-requests-per-endpoint INT`
- `--mutate-sensitive-fields`
- `--allow-invalid-enum-values`
- `--disable-type-confusion`
- `--disable-boundary-values`
- `--disable-null-mutations`

Execution gates:

- `--execute-mutations`
- `--i-understand-mutation-execution-is-authorized`
- `--execute-attacks`
- `--i-understand-this-is-authorized`

Authentication:

- `--auth-bearer-env ENV_VAR`
- `--auth-api-key-env ENV_VAR`
- `--auth-api-key-header HEADER_NAME`
- `--auth-cookie-env ENV_VAR`
- `--auth-cookie-name COOKIE_NAME`
- `--auth-header HEADER_NAME:ENV_VAR`

Analysis:

- `--no-deduplicate-findings`
- `--disable-detector DETECTOR_ID`
- `--analysis-min-confidence CONFIDENCE`

GraphQL:

- `--graphql-max-selection-depth INT`
- `--graphql-max-fields-per-selection INT`
- `--graphql-include-mutations`
- `--graphql-queries-only`
- `--graphql-mutations-only`
- `--graphql-max-operations INT`
- `--graphql-endpoint PATH`
- `--graphql-max-requests INT`
- `--graphql-include-introspection-probe`

Stability:

- `--rate-limit-rps FLOAT`
- `--min-request-delay-ms INT`
- `--max-requests-per-endpoint INT`
- `--max-scan-duration-seconds FLOAT`
- `--retry`
- `--max-retries INT`
- `--retry-status-code INT`
- `--backoff-initial-ms INT`
- `--backoff-max-ms INT`
- `--progress`

## evaluate

```bash
uv run yslfuzz evaluate \
  --report reports/scan.json \
  --ground-truth examples/evaluation/simple_users_ground_truth.json \
  --output-dir reports/evaluation
```

Options:

- `--report PATH`: existing YSLFuzz JSON report.
- `--ground-truth PATH`: JSON/YAML ground-truth file.
- `--output-dir PATH`: directory for JSON and CSV evaluation exports.

## benchmark

```bash
uv run yslfuzz benchmark \
  --config examples/benchmarks/simple_users_benchmark.json \
  --output-dir reports/benchmark \
  --dry-run \
  --overwrite
```

Options:

- `--config PATH`
- `--output-dir PATH`
- `--fail-fast`
- `--dry-run`
- `--overwrite`
- `--verbose`

## labs

```bash
uv run yslfuzz labs list
uv run yslfuzz labs show --lab simple-users
```

Options:

- `--root PATH`: lab catalog root, defaulting to `examples/labs`.
