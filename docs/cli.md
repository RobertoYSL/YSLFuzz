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

Scan Presets:

- `--preset {quick,standard,deep,full}`: Selects an automated intensity preset:
  - `quick`: Stateless sanity check (valid baseline payloads only).
  - `standard`: Stateful baseline fuzzing, dependency-graph workflows, and schema conformance testing.
  - `deep`: Full active fuzzing (stateful workflows, mutations, attacks, BOLA multi-user differential checks, all oracles).
  - `full`: Exhaustive fuzzing with expanded attack payload budgets.
- `--yes`, `-y`: Automatically answer yes to the interactive confirmation prompt for active fuzzing.

Target inputs:

- `--config PATH`: load a JSON/YAML scan configuration profile.
- `--openapi PATH`: local OpenAPI YAML/JSON file.
- `--graphql-schema PATH_OR_URL`: local GraphQL SDL file, local introspection JSON file, or live remote GraphQL endpoint (`http://...`).
- `--base-url URL`: target base URL.
- `--output PATH`: JSON report path.
- `--markdown PATH`: executive Markdown report path.

`--openapi` and `--graphql-schema` are mutually exclusive.

General execution:

- `--max-requests INT`
- `--timeout FLOAT`
- `--allow-destructive`: allow execution of `PUT`, `PATCH`, and `DELETE` endpoints.
- `--dry-run`: plan payloads and requests without sending network traffic.
- `--verbose`: print detailed progress information.

Stateful Workflows:

- `--stateful`, `--enable-workflows`: enable stateful workflow execution derived from the OpenAPI dependency graph (auto-enabled in `standard`, `deep`, `full` presets).

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

- `--execute-mutations`: allow sending mutated payload requests (prompted for confirmation unless `-y` is supplied).
- `--execute-attacks`: allow sending inert attack probe requests (prompted for confirmation unless `-y` is supplied).

Authentication:

- `--auth-bearer-env ENV_VAR`: Bearer token environment variable.
- `--auth-api-key-env ENV_VAR`: API key environment variable.
- `--auth-api-key-header HEADER_NAME`: Header name for API key (default: `X-API-Key`).
- `--auth-cookie-env ENV_VAR`: Cookie value environment variable.
- `--auth-cookie-name COOKIE_NAME`: Cookie name for session.
- `--auth-header HEADER_NAME:ENV_VAR`: Arbitrary header mapping.
- `--auth-user2-bearer-env ENV_VAR`: Second user Bearer token env var for multi-user BOLA/IDOR differential testing.
- `--enable-bola-check`: Enable BOLA multi-user differential oracle (auto-enabled when `--auth-user2-bearer-env` is provided).

Dynamic Authentication Lifecycle:

- `--auth-login-url URL`: Endpoint URL to automatically authenticate before scanning.
- `--auth-login-payload JSON`: Static JSON body for login request.
- `--auth-login-user-env ENV_VAR`: Environment variable containing login username/email.
- `--auth-login-pass-env ENV_VAR`: Environment variable containing login password.
- `--auth-token-field FIELD`: JSON property path to extract authentication token from (default: `token`).
- `--auth-token-type TYPE`: Authorization header prefix (default: `Bearer`).

Analysis & Oracles:

- `--no-deduplicate-findings`: do not group repeated findings by fingerprint.
- `--disable-detector DETECTOR_ID`: disable a specific detector.
- `--analysis-min-confidence CONFIDENCE`: filter findings by minimum confidence level (`LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`).

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
- `--graphql-pagination-limit INT`: limit parameter value for list/collection queries (default: 50).

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
