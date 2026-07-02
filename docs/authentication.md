# Authentication Profiles MVP

YSLFuzz supports safe runtime authentication for REST/OpenAPI scans. Authentication values must come from environment variables. Do not pass raw tokens, cookies, API keys, passwords, or JWTs on the command line or in repository files.

## Supported Modes

- Bearer token header: `Authorization: Bearer <value>`
- API key header: default header `X-API-Key`, or a user-provided header name
- Cookie header: default cookie name `session`, or a user-provided cookie name
- Custom header: one or more `HEADER_NAME:ENV_VAR` mappings

Query-string credentials, OAuth login flows, browser login, token refresh, and secret managers are not part of this MVP. Configuration profiles may reference authentication environment variable names, but never raw credential values.

## CLI Usage

```bash
export YSLFUZZ_TOKEN="<placeholder-token>"
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --auth-bearer-env YSLFUZZ_TOKEN
```

```bash
export YSLFUZZ_API_KEY="<placeholder-api-key>"
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --auth-api-key-env YSLFUZZ_API_KEY \
  --auth-api-key-header X-API-Key
```

```bash
export YSLFUZZ_SESSION="<placeholder-session>"
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --auth-cookie-env YSLFUZZ_SESSION \
  --auth-cookie-name session
```

```bash
export YSLFUZZ_CUSTOM_AUTH="<placeholder-custom-auth>"
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --auth-header X-Custom-Auth:YSLFUZZ_CUSTOM_AUTH
```

Only one authentication mode may be configured per scan. Multiple custom header mappings are allowed as one custom-header mode.

## Safety Guarantees

Authentication values are read from environment variables at runtime and are not persisted in reports, benchmark metadata, lab manifests, test fixtures, or CLI output. Request records store redacted auth markers such as `[REDACTED]`; the HTTP executor receives raw values only for the immediate outbound request.

Reports may include safe metadata:

- `authentication_enabled`
- `authentication_types`
- `auth_sources`
- `auth_redaction_applied`

Reports do not include raw environment variable values. Environment variable names are also omitted from report auth metadata.

## Redaction

Redaction covers common sensitive names including `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `Api-Key`, `API-Key`, `X-Auth-Token`, `X-CSRF-Token`, `access_token`, `refresh_token`, `id_token`, `token`, `jwt`, `session`, `secret`, `password`, `passwd`, and `credential`.

Redaction is applied to request summaries, response summaries, evidence, findings, JSON reports, Markdown reports, benchmark artifacts that contain scan output, and display helpers for resolved auth material.

## Dry Run, Mutations, and Attacks

Dry-run scans do not execute authenticated requests. They may still include safe report metadata indicating that authentication was configured.

Authentication applies to valid requests, mutation requests, attack requests, and workflow requests only when those requests are otherwise allowed to execute. Authentication does not weaken scope validation, destructive method blocking, mutation execution opt-in, or attack execution opt-in.

## Benchmark and Lab Metadata

Benchmark jobs may reference authentication environment variable names with fields such as `auth_bearer_env`, `auth_api_key_env`, `auth_cookie_env`, and `auth_headers`. Benchmark configs must store names only, never values.

Lab manifests may document that authentication is required and list required auth types. Lab packs must not include real credentials, tokens, cookies, API keys, or sample secrets.
