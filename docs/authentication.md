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

## Dynamic Authentication Lifecycle

For APIs that issue short-lived tokens or require dynamic authentication sessions, YSLFuzz can
automatically execute a pre-scan login request, parse the returned JSON response, and inject
the extracted token into all subsequent scan requests.

```bash
export APP_USER="set-this-in-your-shell"
export APP_PASS="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-login-url http://localhost:8000/api/auth/login \
  --auth-login-user-env APP_USER \
  --auth-login-pass-env APP_PASS \
  --auth-token-field token \
  --preset standard \
  --output reports/auth_lifecycle_scan.json
```

Options:
- `--auth-login-url URL`: Login endpoint URL.
- `--auth-login-payload JSON`: Static JSON body for login request.
- `--auth-login-user-env ENV_VAR`: Environment variable for username/email.
- `--auth-login-pass-env ENV_VAR`: Environment variable for password.
- `--auth-token-field FIELD`: JSON response field name or path containing the token (default: `token`).
- `--auth-token-type TYPE`: Authorization header prefix (default: `Bearer`).

## Dual-Identity Multi-User Testing (BOLA / IDOR)

To detect Broken Object Level Authorization (BOLA), YSLFuzz supports multi-user differential testing.
By providing a second user's credentials via `--auth-user2-bearer-env`, the fuzzer automatically
tests authorization boundaries:

```bash
export USER1_TOKEN="set-this-in-your-shell"
export USER2_TOKEN="set-this-in-your-shell"

uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --auth-bearer-env USER1_TOKEN \
  --auth-user2-bearer-env USER2_TOKEN \
  --preset deep \
  -y \
  --output reports/bola_scan.json
```

When enabled, YSLFuzz executes requests using User 1's token to establish the baseline response,
and replicates the request using User 2's token. If User 2 succeeds in accessing User 1's private
resource (receiving HTTP 200 OK instead of 403 Forbidden or 404 Not Found), a BOLA finding is
recorded.

## Redaction

YSLFuzz redacts authentication headers, cookies, and sensitive payload values in reports.
Configuration files should contain env var names only. Do not commit secret values.

## Dry-Run Behavior

Dry-run can validate that an auth profile resolves without sending HTTP requests. The auth
value is still redacted in report metadata.

## Limitations

- One primary auth mode per scan profile.
- No OAuth browser flows.
- No browser automation.
- No query-string credential mode.
- No credential guessing or token mutation.
