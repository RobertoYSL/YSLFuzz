# Configuration

YSLFuzz scan profiles are validated JSON or YAML files loaded with `--config`.
CLI flags override matching configuration values when supplied.

## Top-Level Sections

- `target`: required schema input, API style, and base URL.
- `auth`: optional environment-variable authentication references.
- `payloads`: valid, boundary, invalid, mutated, attack, and GraphQL payload settings.
- `graphql`: GraphQL endpoint, operation generation, execution, and analysis settings.
- `execution`: dry-run, timeout, request limit, destructive guard, and execution gates.
- `analysis`: detector controls.
- `reporting`: report path and output format.
- `limits`: scan-level request, payload, duration, REST, and GraphQL budgets.
- `stability`: rate limiting, retry/backoff, and progress settings.
- `safety`: safety controls that remain enabled by default.
- `metadata`: user-visible scan notes and tags.

## Supported Formats

JSON and YAML are supported. Paths are resolved by the loader and CLI relative to the command
context or the profile path where applicable.

## REST Example

```yaml
target:
  api_style: rest
  openapi_path: examples/openapi/simple_users_api.yaml
  base_url: http://localhost:8000

payloads:
  include_valid_payloads: true
  include_boundary_payloads: true
  include_invalid_payloads: true
  include_attack_payloads: false

execution:
  dry_run: true
  timeout: 5
  max_requests: 25
  allow_destructive: false

reporting:
  output: reports/rest_config_scan.json
```

## GraphQL Example

```yaml
target:
  api_style: graphql
  graphql_schema_path: examples/graphql/simple_users_schema.graphql
  base_url: http://localhost:8000

graphql:
  endpoint_path: /graphql
  include_queries: true
  include_mutations: true
  max_selection_depth: 2
  max_fields_per_selection: 5
  max_requests: 20
  enable_analysis: true
  include_introspection_probe: false

execution:
  dry_run: true

reporting:
  output: reports/graphql_config_scan.json
```

## Authentication References

Configuration stores environment variable names, not secret values:

```yaml
auth:
  bearer_env: YSLFUZZ_TOKEN
```

Only one auth mode is supported per scan profile. See [Authentication](authentication.md).

## Payload Settings

Important payload fields include:

- `include_boundary_payloads`
- `include_invalid_payloads`
- `include_mutated_payloads`
- `include_attack_payloads`
- `enabled_attack_categories`
- `max_mutations_per_payload`
- `max_mutations_per_field`
- `max_attack_requests_per_endpoint`
- `allow_invalid_enum_values`
- `mutate_sensitive_fields`
- `allow_introspection_probe`

Non-valid payload generation is disabled by default.

## Presets and Execution Gates

Configuration profiles can specify scan intensity presets:

```yaml
execution:
  preset: deep
  dry_run: false
  allow_destructive: false
```

When active fuzzing is enabled (`execute_mutations: true` or `execute_attacks: true`), the CLI
prompts for confirmation interactively unless `--yes` / `-y` is supplied at runtime.

Dry-run still prevents all HTTP execution.

## Stability Settings

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
  retry:
    enabled: true
    max_retries: 2
    retry_on_status_codes: [429, 500, 502, 503, 504]
    backoff_initial_ms: 100
    backoff_multiplier: 2.0
    backoff_max_ms: 1000
  progress: true
```

Retries are disabled by default and bounded when enabled.

## Output Format

The supported scan output format in configuration is JSON:

```yaml
reporting:
  output: reports/scan.json
  output_format: json
```

## Limitations

- Configuration profiles support REST or GraphQL targets, not both in one scan.
- Only one auth mode is supported per scan profile.
- Config files must not contain secret values.
- CLI support is the authoritative user interface for flags and overrides.
