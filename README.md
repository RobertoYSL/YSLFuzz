# YSLFuzz

YSLFuzz is a schema-aware fuzzer for authorized REST/OpenAPI and GraphQL API testing.
It turns local API schemas into deterministic payloads, optional HTTP requests, conservative
analysis results, and redacted JSON reports.

> [!IMPORTANT]
> **Legal & Ethical Disclaimer**: YSLFuzz is designed exclusively for authorized security research, educational labs, local development environments, and systems where explicit, written authorization has been granted by the owner. Unauthorized scanning or probing of remote APIs and networks is illegal. The author(s) and contributors assume no liability for misuse, damages, or legal consequences resulting from the use of this software.

## Currently Supported

- REST/OpenAPI discovery from local OpenAPI YAML or JSON files.
- GraphQL discovery from local SDL files, local introspection JSON files, or live remote endpoints (`http://...`).
- Scan intensity presets (`quick`, `standard`, `deep`, `full`) for automated configuration.
- Stateful workflow execution derived from OpenAPI dependency graphs (producer-to-consumer ID/token propagation).
- Valid, boundary, invalid, mutated, and safe attack-classified payload generation.
- Advanced oracles: Baseline Crash Detector (unhandled 500s), Schema Conformance Detector, and Multi-User BOLA/IDOR Differential Testing.
- GraphQL advanced oracles: Field Suggestion Leakage ("Did you mean...") and Boolean SQL Injection differential record-expansion.
- Authentication profiles (Bearer, API Key, Cookie, Custom Headers) and dynamic pre-scan authentication lifecycle.
- Redacted JSON scan reports and executive Markdown reports (`--markdown`).
- Ground-truth evaluation utilities (`yslfuzz evaluate`), benchmark runs, and local lab pack metadata.

YSLFuzz intentionally uses inert markers for attack-classified probes. It does not ship a
real exploit payload library.

## Installation

YSLFuzz requires **Python 3.12+**. Once installed, the standalone `yslfuzz` executable is available globally from any terminal directory.

### Recommended: Standalone CLI (via `pipx` or `uv tool`)

Install directly from the public GitHub repository into an isolated environment without dependency conflicts:

```bash
# Using pipx (recommended for Python CLI tools):
pipx install git+https://github.com/RobertoYSL/YSLFuzz.git

# Or using uv:
uv tool install git+https://github.com/RobertoYSL/YSLFuzz.git
```

Verify that `yslfuzz` is accessible anywhere on your system:

```bash
yslfuzz --help
```

### Option B: Local Clone & Install

```bash
git clone https://github.com/RobertoYSL/YSLFuzz.git
cd YSLFuzz
pip install .
```

### Option C: Development Setup

For local development, testing, and contributions:

```bash
git clone https://github.com/RobertoYSL/YSLFuzz.git
cd YSLFuzz
uv sync
uv run pytest
```

See [Installation Guide](docs/installation.md) for PATH setup, shell completion, and troubleshooting.

## Quickstart

*(Note: If running directly from a development checkout without global installation, prefix commands with `uv run yslfuzz ...`)*

REST scan with presets:

```bash
# Quick stateless sanity check
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset quick \
  --output reports/rest_quick.json

# Standard scan with stateful workflows and schema conformance
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset standard \
  --output reports/rest_standard.json

# Deep active fuzzing (mutations, attacks, oracles) with executive Markdown report
yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset deep \
  -y \
  --output reports/rest_deep.json \
  --markdown reports/rest_deep.md
```

GraphQL scan (local schema or live endpoint):

```bash
# Live remote GraphQL endpoint
yslfuzz scan \
  --graphql-schema http://localhost:5013/graphql \
  --preset deep \
  -y \
  --output reports/graphql_deep.json \
  --markdown reports/graphql_deep.md
```

Evaluation against ground truth:

```bash
yslfuzz evaluate \
  --report reports/rest_deep.json \
  --ground-truth examples/evaluation/crapi_ground_truth.json \
  --output-dir reports/evaluation
```

## CLI

Top-level commands:

- `yslfuzz scan`: discover schemas, generate payloads, optionally execute requests, analyze responses, and write reports.
- `yslfuzz evaluate`: compare a YSLFuzz JSON report with a ground-truth file.
- `yslfuzz benchmark`: run configured benchmark jobs.
- `yslfuzz labs`: list and inspect local lab packs.

See [CLI Reference](docs/cli.md).

## Safety Model

YSLFuzz keeps risky behavior opt-in:

- Dry-run mode (`--dry-run`) validates schemas and payloads without sending HTTP traffic.
- Interactive confirmation prompt (`[y/N]`) protects active mutation and attack scans (auto-confirmed with `-y` / `--yes`).
- Destructive REST methods (`DELETE`, `PUT`, `PATCH`) require `--allow-destructive`.
- Request budgets, endpoint budgets, rate limiting, retry bounds, and global scan duration limits keep scans stable.
- Authentication credentials and sensitive payload fields are strictly redacted in logs, reports, and console outputs.

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
markers only. OAuth browser flows, browser automation, WebSocket subscriptions,
multipart GraphQL upload, persistent resume, and release automation are not
current core features.

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).

