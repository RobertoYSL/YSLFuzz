# YSLFuzz

YSLFuzz is a schema-aware stateful fuzzer for REST and GraphQL APIs.

This repository is currently at Milestone 0: project bootstrap. The package
structure and Python tooling are present, but parsing, fuzzing, execution,
analysis, reporting, and data models are intentionally not implemented yet.

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
