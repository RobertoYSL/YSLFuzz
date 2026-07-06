# Configuration Profiles MVP

YSLFuzz scan configuration profiles let a scan be defined in a local JSON or YAML file and executed with:

```bash
yslfuzz scan --config examples/configs/simple_users_dry_run.json
```

JSON is supported. YAML is also supported because YSLFuzz already depends on PyYAML.

## Schema

Top-level sections:

- `target`: `openapi_path`, `base_url`, optional `api_style`, `target_id`, `target_name`
- `auth`: environment-variable references for bearer, API key header, cookie, or custom headers
- `payloads`: payload generation modes and limits
- `graphql`: GraphQL endpoint, payload-generation limits, and GraphQL request limits
- `execution`: dry-run, timeout, request limit, destructive-method and execution opt-ins
- `analysis`: disabled detectors and minimum confidence
- `reporting`: output path and output format
- `limits`: optional request, endpoint, and payload budgets
- `stability`: rate limiting, retry/backoff, and progress settings
- `safety`: authorization-gate and redaction controls
- `metadata`: scan name, notes, and tags

Configuration profiles support REST/OpenAPI scans and local GraphQL schema scans. GraphQL settings
cover discovery, valid payload generation, execution, safe non-valid payload generation, inert marker
attack payload generation, and conservative GraphQL analysis.

## Safe Defaults

When a config file is used:

- `dry_run = true`
- `allow_destructive = false`
- `execute_attacks = false`
- `execute_mutations = false`
- attack, boundary, invalid, and mutated payload modes are disabled unless explicitly enabled
- `mutate_sensitive_fields = false`
- `redact_secrets = true`
- auth entries are environment variable names only
- GraphQL endpoint defaults to `/graphql`
- GraphQL config execution remains governed by `execution.dry_run`

Existing CLI behavior is preserved when `--config` is not used.

## Path Resolution

Relative `target.openapi_path` and `reporting.output` paths are resolved relative to the config file directory.

For example, in `examples/configs/simple_users_dry_run.json`:

```json
{
  "target": {
    "openapi_path": "../openapi/simple_users_api.yaml"
  },
  "reporting": {
    "output": "simple_users_dry_run_report.json"
  }
}
```

The OpenAPI path resolves under `examples/openapi/`, while the report path resolves under `examples/configs/`.

## CLI Overrides

CLI flags override config values when explicitly provided. Supported overrides include target paths, output path, request limits, timeout, dry-run, payload mode flags, execution flags, auth flags, attack categories, mutation limits, and detector flags.

Example:

```bash
yslfuzz scan \
  --config examples/configs/simple_users_dry_run.json \
  --output out/report.json \
  --dry-run
```

`--dry-run` only forces dry-run on. There is no CLI flag in this MVP to force a config dry-run value to false.

## Authentication

Config files may reference auth environment variable names:

```json
{
  "auth": {
    "bearer_env": "YSLFUZZ_TOKEN"
  }
}
```

The resolver reads the environment value only at execution time. Config files must not contain raw tokens, cookies, API keys, passwords, JWTs, or query-string credentials.

## Authorization Gates

If a merged config enables attack execution, it must also set:

```json
{
  "execution": {
    "execute_attacks": true,
    "i_understand_attack_execution_is_authorized": true
  }
}
```

If a merged config enables mutation execution, it must also set:

```json
{
  "execution": {
    "execute_mutations": true,
    "i_understand_mutation_execution_is_authorized": true
  }
}
```

The equivalent CLI acknowledgement flags can satisfy these gates after config loading and CLI override merging.

Dry-run still prevents HTTP execution.

## GraphQL Configuration

GraphQL profiles use `target.api_style = "GRAPHQL"` and `target.graphql_schema_path`.

```json
{
  "target": {
    "api_style": "GRAPHQL",
    "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
    "base_url": "http://localhost:8080"
  },
  "graphql": {
    "endpoint_path": "/graphql",
    "max_selection_depth": 2,
    "max_fields_per_selection": 5,
    "include_queries": true,
    "include_mutations": true,
    "max_requests": 20,
    "enable_analysis": true,
    "include_introspection_probe": false
  },
  "payloads": {
    "include_boundary_payloads": true,
    "include_invalid_payloads": true,
    "include_mutated_payloads": false,
    "include_attack_payloads": false,
    "max_mutations_per_payload": 10,
    "max_mutations_per_field": 3,
    "allow_invalid_enum_values": false,
    "mutate_sensitive_fields": false,
    "allow_extra_input_fields": true,
    "allow_missing_required_fields": true,
    "enabled_attack_categories": [
      "INPUT_VALIDATION",
      "INFORMATION_DISCLOSURE",
      "SQL_INJECTION",
      "NOSQL_INJECTION",
      "COMMAND_INJECTION",
      "SSRF"
    ]
  },
  "analysis": {
    "enable_graphql_error_disclosure": true,
    "enable_graphql_validation_bypass": true,
    "enable_graphql_introspection_exposure": true,
    "enable_graphql_reflection_detection": true,
    "enable_graphql_mass_assignment_detection": true,
    "enable_graphql_authorization_consistency": true,
    "enable_graphql_injection_marker_detection": true,
    "enable_graphql_ssrf_marker_detection": true
  },
  "execution": {
    "dry_run": true,
    "timeout": 5,
    "max_requests": 50
  },
  "limits": {
    "max_requests": 50,
    "max_requests_per_endpoint": 10,
    "max_duration_seconds": 60,
    "max_graphql_requests": 25
  },
  "stability": {
    "rate_limit_rps": 2.0,
    "min_request_delay_ms": 100,
    "progress": true,
    "retry": {
      "enabled": true,
      "max_retries": 2,
      "retry_on_status_codes": [429, 500, 502, 503, 504],
      "backoff_initial_ms": 100,
      "backoff_multiplier": 2.0,
      "backoff_max_ms": 1000
    }
  },
  "reporting": {
    "output": "graphql_report.json"
  }
}
```

`execution.dry_run` applies to GraphQL. When dry-run is true, YSLFuzz builds planned GraphQL request
records and executes zero HTTP requests. If both `graphql.max_requests` and `execution.max_requests`
are set, the stricter limit is used.

## Stability Configuration

`limits.max_requests` maps to `execution.max_requests` when `execution.max_requests` is omitted.
`limits.max_requests_per_endpoint` caps planned requests per endpoint. `limits.max_duration_seconds`
stops scheduling new requests after the configured duration and records partial report metadata.

`stability.rate_limit_rps` and `stability.min_request_delay_ms` pace real HTTP execution. They do
not cause dry-run sleeps. `stability.retry.enabled` must be true before retry settings take effect.
Retries are bounded and disabled by default.

## Reporting Metadata

Reports include safe config metadata:

- `config_file_used`
- `config_profile_name`
- `config_hash`
- `config_loaded_at`
- `config_enabled_modes`

Reports do not include the full config file or raw secret values. The config hash is deterministic over normalized validated config content and excludes runtime timestamps and the config file path.

## Benchmark Relation

Benchmark configs remain separate from scan configuration profiles for this MVP. The benchmark harness keeps its existing job schema.

## Limitations

- GraphQL active authorization probe execution is not implemented; analysis can consume explicitly paired records.
- GraphQL analysis is conservative and does not confirm vulnerabilities.
- GraphQL SQL, NoSQL, command and SSRF category support uses inert markers only.
- KeyboardInterrupt partial-report cancellation is not implemented.
- No config inheritance or profile composition.
- No remote config URLs.
- No secret manager integration.
- No OAuth, token refresh, browser login, or query-string credentials.
- JSON and YAML files are local only.
