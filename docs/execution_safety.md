# Execution Safety

YSLFuzz is for authorized testing only. Always verify that you own the target or have written
permission to test it.

## Dry-Run

Dry-run mode generates payloads and planned requests but executes zero HTTP requests. Use it
first when validating a schema, configuration file, or report path.

## Scope and Schema Inputs

Schemas are loaded from local files. REST scans use `--openapi`; GraphQL scans use
`--graphql-schema`. The two target inputs are mutually exclusive.

## Destructive Method Guard

REST `PUT`, `PATCH`, and `DELETE` execution is blocked unless destructive execution is
explicitly allowed. This is separate from mutation payload execution.

## Mutation and Attack Execution Gates

Active fuzzing involves generating edge-case mutations and attack probes that could alter
server state or produce unexpected errors. YSLFuzz enforces clear execution boundaries:

1. **Preset-driven Execution**: When running with `--preset deep` or `--preset full` (or with explicit
   `--execute-mutations` / `--execute-attacks`), the CLI checks if active fuzzing is enabled.
2. **Interactive Confirmation Prompt**: If active fuzzing is requested, YSLFuzz displays a warning
   banner detailing what actions will be performed (e.g. sending boundary values, injection probes,
   and stateful mutations) and prompts for confirmation:
   ```text
   Proceed with active fuzzing? [y/N]:
   ```
3. **Automated Runs (`--yes` / `-y`)**: In automated test suites, CI/CD pipelines, or benchmark
   workflows, supply `--yes` or `-y` to automatically confirm authorization.

`--execute-mutations` and `--execute-attacks` can also be toggled independently in custom scan configs.

## Request Budgets and Stability

Use request limits, endpoint limits, GraphQL request limits, global duration limits, rate
limits, and retry bounds to keep scans predictable. Dry-run skips execution before rate
limiting and retry logic.

## Redaction

Authentication values are read from environment variables and injected at execution time.
Reports, logs, and serialized models redact sensitive headers, cookies, and body fields.
Configuration files should store environment variable names, not secret values.

## Safe Marker Philosophy

Attack-classified probes use inert YSLFuzz markers. The goal is to observe validation,
reflection, and error-handling signals without using operational exploit payloads.

## Prohibited Payload Classes

The current product does not generate real SQL, NoSQL, command execution, cloud metadata,
internal network, credential guessing, brute force, batching abuse, fragment explosion, or
DoS-style payloads.

## Tests

Project tests must be local and deterministic. Network behavior in tests uses mocks or local
handlers only.
