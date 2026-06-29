# YSLFuzz

YSLFuzz is a schema-aware stateful fuzzer for REST and GraphQL APIs.

This repository contains the MVP vertical slice:

OpenAPI file -> internal schema -> valid payload generation -> HTTP execution
records -> JSON report.

## Development

Required Python version:

```bash
python 3.12
```

Run the smoke test:

```bash
python -m pytest
```

If using uv:

```bash
uv run pytest
```

## CLI

Show help:

```bash
uv run yslfuzz --help
uv run yslfuzz scan --help
```

Run a dry scan that parses an OpenAPI file, generates valid payloads, and writes
a JSON report without sending HTTP requests:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --output report.json \
  --dry-run
```

By default, `DELETE`, `PUT`, and `PATCH` endpoints are skipped. Use
`--allow-destructive` only for explicitly authorized test targets.
