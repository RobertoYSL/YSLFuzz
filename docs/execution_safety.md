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

Mutation payload execution requires:

- `--execute-mutations`
- `--i-understand-mutation-execution-is-authorized`

Attack payload execution requires:

- `--execute-attacks`
- `--i-understand-this-is-authorized`

`--execute-mutations` does not imply `--execute-attacks`, and `--execute-attacks` does not
imply `--execute-mutations`.

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
