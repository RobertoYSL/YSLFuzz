# GraphQL Examples

This directory contains small local GraphQL schema fixtures:

- `simple_users_schema.graphql`: SDL schema.
- `simple_users_introspection.json`: local introspection JSON fixture.

## Dry-Run Scan

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/graphql_dry_run.json
```

## Custom Endpoint

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --graphql-endpoint /graphql \
  --dry-run \
  --output reports/graphql_endpoint_dry_run.json
```

## Safe Marker Generation

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --include-attack-payloads \
  --dry-run \
  --output reports/graphql_attack_markers.json
```

Attack marker execution still requires `--execute-attacks` and
`--i-understand-this-is-authorized`.

## Introspection Probe

Introspection probes are disabled by default. Generate one only with explicit opt-in:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --graphql-include-introspection-probe \
  --include-attack-payloads \
  --dry-run \
  --output reports/graphql_introspection_probe.json
```

No real endpoints or credentials are included in these examples.
