# GraphQL Examples

This directory contains local-only GraphQL schema examples for GraphQL discovery and valid payload
generation.

- `simple_users_schema.graphql` is a small SDL schema.
- `simple_users_introspection.json` is a minimal introspection JSON document.

Generate discovery and valid payload summaries without executing HTTP requests:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
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
intended for parser, mapper, payload generation, CLI, and documentation tests only.
