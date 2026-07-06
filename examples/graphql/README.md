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

Generate boundary payloads in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-boundary-payloads \
  --dry-run \
  --output graphql_boundary_report.json
```

Generate invalid payloads in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-invalid-payloads \
  --dry-run \
  --output graphql_invalid_report.json
```

Generate inert attack-classified probes in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --dry-run \
  --output graphql_attack_generation_report.json
```

Generate safe marker probes for selected categories in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --attack-category SQL_INJECTION \
  --attack-category NOSQL_INJECTION \
  --attack-category COMMAND_INJECTION \
  --attack-category SSRF \
  --dry-run \
  --output graphql_safe_marker_report.json
```

The generated values are inert YSLFuzz markers. They do not contain SQL syntax, NoSQL operators,
shell commands, localhost URLs, private IPs, link-local addresses, cloud metadata hosts, or callback
domains.

Generate the bounded introspection probe only when explicitly enabled:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --attack-category GRAPHQL_INTROSPECTION_ABUSE \
  --graphql-include-introspection-probe \
  --dry-run \
  --output graphql_introspection_probe_report.json
```

Execute mutated GraphQL payloads only against an authorized local or mock endpoint:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-mutated-payloads \
  --execute-mutations \
  --i-understand-mutation-execution-is-authorized \
  --output graphql_mutation_exec_report.json
```

Attack-classified GraphQL probes require `--execute-attacks` and
`--i-understand-this-is-authorized`. They use inert markers only and should be used only against
authorized local or mock endpoints.

GraphQL analysis runs after executed GraphQL non-valid or attack payloads have responses. Dry-run
reports include generated and planned probe summaries but no findings because no HTTP responses are
received.

Authorization consistency analysis is passive in these examples. It can analyze explicitly paired
auth/no-auth or alternate-profile records, but this milestone does not add active credential
mutation, brute force, or silent unauthenticated execution.

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
