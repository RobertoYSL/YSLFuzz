# Roadmap

This page reflects the current practical roadmap, not older milestone lists in pre-development
references.

## Completed Milestones

- REST/OpenAPI schema discovery, payload generation, and execution.
- Stateful dependency graph analysis and automated workflow execution.
- Scan intensity presets (`quick`, `standard`, `deep`, `full`) and interactive authorization confirmation.
- Advanced detection oracles:
  - `BaselineCrashDetector` (identifying 500 crashes on compliant requests).
  - `SchemaConformanceDetector` (identifying undocumented codes, schema drift, and data exposure).
  - Multi-user differential testing for Broken Object Level Authorization (BOLA/IDOR).
- GraphQL engine:
  - Local SDL, introspection JSON, and live remote HTTP schema loading.
  - Operation, variable, selection, boundary, mutation, and attack generation.
  - `GraphQLFieldSuggestionDetector` (enumerating schema fields via "Did you mean...").
  - `GraphQLBooleanSqlInjectionDetector` (differential result set expansion on HTTP 200).
- Authentication:
  - Static auth profiles (Bearer, API Key, Cookie, Custom Headers).
  - Dynamic pre-scan authentication lifecycle (`--auth-login-url`).
  - Dual-identity token support (`--auth-user2-bearer-env`).
- Reporting:
  - Redacted machine-readable JSON reports.
  - Executive Markdown reports (`--markdown`).
  - Terminal scan summary banner with severity breakdown.
- Evaluation and benchmarking:
  - `yslfuzz evaluate` matching engine, metrics (Precision, Recall, F1), and artifact exports.
  - Predefined benchmark ground truths for OWASP crAPI and mock evaluation labs.
- Performance, stability, rate limiting, retry/backoff bounds, and progress tracking.
- Documentation, architecture reference, and user manual.

## Removed from the Core Product

- Third-party baseline comparison as an internal YSLFuzz feature (handled externally).
- Thesis experiment runner as an internal YSLFuzz feature (orchestrated externally via evaluation exports).

## Optional Future Work

- Interactive HTML dashboards.
- Continuous integration and automated release packaging.
- Advanced GraphQL features such as subscriptions, if safe and explicitly scoped.
- OAuth token refresh lifecycle flows.
