# Authentication

YSLFuzz authentication profiles reference environment variables. Secret values are read at
execution time and redacted in reports and serialized models.

Only run authenticated scans against targets you are authorized to test.

## Bearer Token

```bash
export YSLFUZZ_TOKEN="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-bearer-env YSLFUZZ_TOKEN \
  --dry-run \
  --output reports/auth_bearer_dry_run.json
```

Config:

```yaml
auth:
  bearer_env: YSLFUZZ_TOKEN
```

## API Key Header

```bash
export YSLFUZZ_API_KEY="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-api-key-env YSLFUZZ_API_KEY \
  --auth-api-key-header X-API-Key \
  --dry-run \
  --output reports/auth_api_key_dry_run.json
```

Config:

```yaml
auth:
  api_key_env: YSLFUZZ_API_KEY
  api_key_header: X-API-Key
```

## Cookie

```bash
export YSLFUZZ_SESSION="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-cookie-env YSLFUZZ_SESSION \
  --auth-cookie-name session \
  --dry-run \
  --output reports/auth_cookie_dry_run.json
```

Config:

```yaml
auth:
  cookie_env: YSLFUZZ_SESSION
  cookie_name: session
```

## Custom Header

```bash
export YSLFUZZ_CUSTOM_AUTH="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-header X-Custom-Auth:YSLFUZZ_CUSTOM_AUTH \
  --dry-run \
  --output reports/auth_custom_header_dry_run.json
```

Config:

```yaml
auth:
  custom_headers:
    - X-Custom-Auth:YSLFUZZ_CUSTOM_AUTH
```

## Redaction

YSLFuzz redacts authentication headers, cookies, and sensitive payload values in reports.
Configuration files should contain env var names only. Do not commit secret values.

## Dry-Run Behavior

Dry-run can validate that an auth profile resolves without sending HTTP requests. The auth
value is still redacted in report metadata.

## Limitations

- One auth mode per scan profile.
- No OAuth login flow.
- No token refresh.
- No browser automation.
- No query-string credential mode.
- No credential guessing or token mutation.
