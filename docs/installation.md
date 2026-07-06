# Installation

YSLFuzz is developed for Python 3.12.

## Repository Setup

From the repository root:

```bash
uv sync
uv run yslfuzz --help
uv run pytest
```

If `uv` is not available, install it using the process approved for your environment.
The repository also supports standard Python tooling through `pyproject.toml`, but the
documented development path is `uv run ...`.

## Development Checks

Run the local checks before submitting changes:

```bash
uv run pytest
uv run ruff check .
uv run mypy yslfuzz
```

The same commands are valid smoke checks for a fresh checkout.

## CLI Smoke Checks

```bash
uv run yslfuzz --help
uv run yslfuzz scan --help
uv run yslfuzz evaluate --help
uv run yslfuzz benchmark --help
uv run yslfuzz labs --help
```

## Troubleshooting

- Use Python 3.12. Older Python versions are not part of the supported test matrix.
- Run commands from the repository root so example paths resolve as documented.
- If dependency resolution fails, refresh the local `uv` environment with `uv sync`.
- If a scan writes no report, check that `--output` is set and that the schema path exists.
- If an authenticated scan has no auth header, confirm that the referenced environment
  variable is set. YSLFuzz stores env var names in config, not secret values.

Release packaging and automation are not documented as complete product features here.
