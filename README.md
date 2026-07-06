# YSLFuzz

YSLFuzz is a schema-aware fuzzer for authorized REST/OpenAPI and GraphQL API testing.
It turns local API schemas into deterministic payloads, optional HTTP requests, conservative
analysis results, and redacted JSON reports.

YSLFuzz is intended for local labs, owned services, and explicitly authorized assessment
work only. Do not run it against systems you do not have permission to test.

## Currently Supported

- REST/OpenAPI discovery from local OpenAPI YAML or JSON files.
- GraphQL discovery from local SDL files and local introspection JSON files.
- Valid, boundary, invalid, mutated, and safe attack-classified payload generation.
- GraphQL valid payloads, GraphQL execution, safe marker probes, and signal-based GraphQL analysis.
- Authentication profiles using environment variable references.
- Scan configuration profiles in JSON or YAML.
- Dry-run mode, request budgets, rate limiting, retry/backoff controls, and progress snapshots.
- Redacted JSON scan reports.
- Ground-truth evaluation utilities, benchmark runs, and local lab pack metadata.

YSLFuzz intentionally uses inert markers for attack-classified probes. It does not ship a
real exploit payload library.

## Install

Use Python 3.12. During development, run commands through `uv` from the repository root:

```bash
uv sync
uv run yslfuzz --help
uv run pytest
```

See [Installation](docs/installation.md) for details and troubleshooting.

## Quickstart

REST/OpenAPI dry-run:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/rest_dry_run.json
```

GraphQL dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --dry-run \
  --output reports/graphql_dry_run.json
```

Safe attack-classified payload generation in dry-run:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --include-attack-payloads \
  --dry-run \
  --output reports/attack_generation.json
```

Dry-run builds payloads and planned requests but does not send HTTP traffic.

## CLI

Top-level commands:

- `yslfuzz scan`: discover schemas, generate payloads, optionally execute requests, analyze responses, and write reports.
- `yslfuzz evaluate`: compare a YSLFuzz JSON report with a ground-truth file.
- `yslfuzz benchmark`: run configured benchmark jobs.
- `yslfuzz labs`: list and inspect local lab packs.

See [CLI Reference](docs/cli.md).

## Safety Model

YSLFuzz keeps risky behavior opt-in:

- Dry-run is supported and should be the first mode used on a target.
- Destructive REST methods require `--allow-destructive`.
- Mutation payload execution requires `--execute-mutations` and an authorization acknowledgement.
- Attack payload execution requires `--execute-attacks` and an authorization acknowledgement.
- Request budgets, endpoint budgets, rate limiting, retry bounds, and global scan duration limits are available.
- Authentication material is read from environment variables and redacted in reports.

See [Execution Safety](docs/execution_safety.md).

## Documentation

Start with [Documentation Index](docs/index.md).

Core guides:

- [Quickstart](docs/quickstart.md)
- [CLI Reference](docs/cli.md)
- [Configuration](docs/configuration.md)
- [Authentication](docs/authentication.md)
- [REST/OpenAPI](docs/rest_openapi.md)
- [GraphQL](docs/graphql.md)
- [Payloads](docs/payloads.md)
- [Reporting](docs/reporting.md)
- [Performance and Stability](docs/performance.md)
- [Architecture](docs/architecture.md)
- [Development](docs/development.md)
- [Limitations](docs/limitations.md)
- [Roadmap](docs/roadmap.md)

## Research Context

YSLFuzz is developed as a research-oriented API fuzzing tool. It provides deterministic
outputs, evaluation exports, and benchmark/lab support so scan behavior can be reviewed and
reproduced. Third-party baseline comparison and thesis experiment orchestration are handled
outside the core product.

## Limitations

YSLFuzz is not a replacement for manual security review. Analysis is conservative and
signal-based. GraphQL safe SQL, NoSQL, command, and SSRF category coverage uses inert
markers only. OAuth login flows, browser automation, live remote introspection, WebSocket
subscriptions, multipart GraphQL upload, persistent resume, and release automation are not
current core features.
