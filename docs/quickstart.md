# Quickstart

All examples use local files from `examples/` or local authorization testbeds. Replace the
base URL only with a service you are authorized to test.

## REST Scans Using Presets

YSLFuzz provides intensity presets that simplify configuration:

### 1. Quick Scan (Stateless Reconnaissance)

Send valid baseline payloads only to verify endpoint reachability and catch unhandled 500
crashes on compliant requests:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset quick \
  --output reports/rest_quick.json
```

### 2. Standard Scan (Stateful Workflows & Conformance)

Execute stateful producer-to-consumer dependency workflows to populate dynamic IDs, and verify
OpenAPI schema conformance on all server responses:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset standard \
  --output reports/rest_standard.json
```

### 3. Deep Scan (Active Fuzzing & Oracles)

Activate boundary edge-cases, type mutations, safe attack-classified probes, multi-user BOLA
checks, and generate both JSON and executive Markdown reports:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset deep \
  -y \
  --output reports/rest_deep.json \
  --markdown reports/rest_deep.md
```

Note: Active fuzzing prompts for confirmation unless `-y` or `--yes` is supplied.

## REST Dry-Run

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/rest_dry_run.json
```

Dry-run builds payloads and planned requests but does not send HTTP traffic.

## GraphQL Scans

### Local Schema File

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --preset deep \
  -y \
  --output reports/graphql_scan.json \
  --markdown reports/graphql_scan.md
```

### Live Remote GraphQL Endpoint

You can directly pass an HTTP endpoint URL to `--graphql-schema` to load the schema:

```bash
uv run yslfuzz scan \
  --graphql-schema http://localhost:5013/graphql \
  --preset deep \
  -y \
  --output reports/graphql_remote.json \
  --markdown reports/graphql_remote.md
```

## Evaluating Findings against Ground Truth

Compare a scan report with a ground-truth dataset to compute precision, recall, and F1 metrics:

```bash
uv run yslfuzz evaluate \
  --report reports/rest_deep.json \
  --ground-truth examples/evaluation/crapi_ground_truth.json \
  --output-dir reports/evaluation
```

## Reading the Report

Reports are provided in two formats:
- **Redacted JSON** (`--output`): Comprehensive machine-readable report containing scan metadata, reproducible seeds, request/response records, and detailed findings.
- **Executive Markdown** (`--markdown`): Human-readable summary table, severity breakdown, top vulnerable endpoints, and formatted evidence previews.
