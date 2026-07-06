# Quickstart

All examples use local files from `examples/`. Replace the base URL only with a service
you are authorized to test.

## REST/OpenAPI Dry-Run

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/rest_dry_run.json
```

This parses the OpenAPI file, generates valid payload candidates, builds planned requests,
and writes a JSON report without sending HTTP requests.

## REST Boundary, Invalid, and Mutated Payloads

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --include-boundary-payloads \
  --include-invalid-payloads \
  --include-mutated-payloads \
  --dry-run \
  --output reports/rest_mutation_dry_run.json
```

Mutation payload execution is disabled unless `--execute-mutations` and
`--i-understand-mutation-execution-is-authorized` are both supplied.

## REST Safe Attack Payload Generation

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --include-attack-payloads \
  --dry-run \
  --output reports/rest_attack_generation.json
```

Attack payload execution is disabled unless `--execute-attacks` and
`--i-understand-this-is-authorized` are both supplied.

## GraphQL Dry-Run

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/graphql_dry_run.json
```

GraphQL schemas can be SDL files or local introspection JSON files. Dry-run generates
operation payloads and planned POST requests but sends nothing.

## GraphQL Execution

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --graphql-endpoint /graphql \
  --max-requests 10 \
  --output reports/graphql_scan.json
```

Without `--dry-run`, valid GraphQL payloads can be executed as JSON POST requests. Non-valid
GraphQL payloads still require the same mutation or attack execution gates as REST payloads.

## Reading the Report

Reports are JSON. Common top-level fields include scan metadata, metrics, summaries,
findings, responses, generated payload counts, GraphQL summaries when applicable, and
stability information such as skipped request counts.

```bash
python -m json.tool reports/rest_dry_run.json
```
