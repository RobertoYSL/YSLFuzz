# GraphQL Examples

This directory contains local-only GraphQL schema examples for GraphQL discovery, valid payload
generation, and GraphQL execution against authorized local endpoints.

- `simple_users_schema.graphql` is a small SDL schema.
- `simple_users_introspection.json` is a minimal introspection JSON document.

Plan discovery, valid payloads, and GraphQL requests without executing HTTP requests:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --dry-run \
  --output graphql_report.json
```

Execute against an authorized local or mock GraphQL endpoint:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --graphql-endpoint /graphql \
  --graphql-max-requests 20 \
  --output graphql_report.json
```

Use a non-default GraphQL endpoint path:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --graphql-endpoint /api/graphql \
  --dry-run \
  --output graphql_report.json
```

Use authentication safely with environment variable references:

```bash
export YSLFUZZ_TOKEN="<placeholder-token>"
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --graphql-endpoint /graphql \
  --auth-bearer-env YSLFUZZ_TOKEN \
  --dry-run \
  --output graphql_report.json
```

Example generated payload body:

```json
{
  "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email name role } }",
  "variables": {
    "id": "yslfuzz-id-001"
  },
  "operationName": "YSLFuzzUser"
}
```

These examples do not include real endpoints, credentials, tokens, cookies, or API keys. They are
intended for parser, mapper, payload generation, execution wiring, CLI, and documentation tests only.
