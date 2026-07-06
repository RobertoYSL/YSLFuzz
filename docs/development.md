# Development

## Repository Layout

- `yslfuzz/`: package source.
- `tests/`: unit and integration tests.
- `examples/`: local schemas, configs, labs, and benchmark inputs.
- `docs/`: current docs and pre-development design references.

## Local Checks

```bash
uv run pytest
uv run ruff check .
uv run mypy yslfuzz
```

Also smoke-check CLI help after CLI-facing changes:

```bash
uv run yslfuzz --help
uv run yslfuzz scan --help
uv run yslfuzz evaluate --help
uv run yslfuzz benchmark --help
uv run yslfuzz labs --help
```

## Adding a Detector

1. Define a small detector with explicit input assumptions.
2. Emit conservative severity and confidence.
3. Keep evidence bounded and redacted.
4. Add unit tests for positive and negative cases.
5. Register it only for matching API styles.

## Adding a Payload Generator

1. Preserve deterministic output.
2. Use safe defaults and bounded counts.
3. Preserve `parent_payload_id` for derived payloads.
4. Avoid secrets and operational exploit strings.
5. Add unit tests for values, metadata, limits, and safety.

## Adding a CLI Flag

1. Add parser help text that describes actual behavior.
2. Map it to config or execution models.
3. Ensure config profiles and CLI overrides remain predictable.
4. Add help or behavior tests.

## Test Expectations

Tests must be local and deterministic. Do not add external network calls. Use mock transports,
local handlers, fake clocks, and fake sleepers for execution, retry, timeout, and rate limit
tests.

## Safety Review

Any change that affects execution, authentication, mutation payloads, attack payloads,
redaction, scope, or reports should be reviewed for safe defaults and opt-in behavior.
