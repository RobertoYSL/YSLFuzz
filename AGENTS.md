# AGENTS.md

# YSLFuzz Development Instructions

## Project identity

This repository contains YSLFuzz, a schema-aware stateful fuzzer for REST and GraphQL APIs.

The project must be implemented according to the documentation in:

- docs/predev/00_adr_architecture_decision_record.md
- docs/predev/01_sdd_software_design_document.md
- docs/predev/02_dms_data_model_specification.md
- docs/predev/03_attack_coverage_matrix.md
- docs/predev/04_threat_model_stride.md
- docs/predev/05_evaluation_plan.md
- docs/predev/06_test_strategy_and_quality_plan.md
- docs/predev/07_product_backlog_milestones.md
- docs/predev/08_development_kickoff_spec.md
- docs/predev/09_definition_of_done_and_readiness_checklist.md

## Development rules

1. Do not implement features that are not described in the documentation unless explicitly requested.
2. Prefer incremental, testable changes.
3. Every new module must have unit tests.
4. Every public function or class must have type hints.
5. Use Python 3.12.
6. Use Pydantic for core data models.
7. Use httpx for HTTP execution.
8. Use pytest for tests.
9. Do not add network calls in tests unless they use a local mock server.
10. Do not store secrets, tokens, cookies, API keys, passwords or JWTs in plaintext.
11. Redact sensitive values in logs, reports and test outputs.
12. Do not implement destructive scanning behavior by default.
13. DELETE, PUT and PATCH execution must be guarded by explicit configuration.
14. The first MVP must focus on REST/OpenAPI before expanding to GraphQL.
15. Keep the codebase modular and aligned with the SDD package structure.

## Expected repository structure

Use this structure unless the documentation requires a justified change:

yslfuzz/
├── yslfuzz/
│   ├── __init__.py
│   ├── models/
│   ├── discovery/
│   ├── schema/
│   ├── dependency/
│   ├── payloads/
│   ├── execution/
│   ├── analysis/
│   ├── reporting/
│   └── cli/
├── tests/
├── examples/
├── benchmarks/
├── docs/
│   └── predev/
├── pyproject.toml
├── README.md
└── AGENTS.md

## Coding style

- Use clear names.
- Keep functions small.
- Prefer explicit data models over dictionaries when data crosses module boundaries.
- Prefer pure functions where possible.
- Avoid global mutable state.
- Use dependency injection for components that perform I/O.
- Keep dangerous behavior opt-in.

## Validation commands

Before considering a task complete, run:

python -m pytest

If available, also run:

python -m ruff check .
python -m mypy yslfuzz

## Implementation strategy

Work in vertical slices.

First vertical slice:

OpenAPI schema
→ internal ApiSchema model
→ valid payload generation
→ HTTP request record
→ response record
→ JSON report

Do not start with the full fuzzer. Build the smallest working pipeline first.