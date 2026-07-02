# YSLFuzz Authentication Examples

These examples use environment variable names only. Replace placeholder values in your shell or CI secret store, not in repository files.

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
  --auth-api-key-env YSLFUZZ_API_KEY
```

```bash
export YSLFUZZ_SESSION="<placeholder-session>"
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --auth-cookie-env YSLFUZZ_SESSION
```

Do not commit files containing real credentials.
