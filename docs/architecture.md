# Architecture

YSLFuzz is organized as a set of small layers around shared Pydantic models.

## Layers

- `yslfuzz.discovery`: REST/OpenAPI discovery and schema normalization.
- `yslfuzz.discovery.graphql`: GraphQL SDL and introspection JSON discovery.
- `yslfuzz.payloads`: REST valid, boundary, invalid, mutated, and attack payload generation.
- `yslfuzz.payloads.graphql`: GraphQL operation, variable, selection, mutation, and safe marker generation.
- `yslfuzz.execution`: HTTP request building, execution, budgets, retry, rate limiting, and progress tracking.
- `yslfuzz.execution.graphql`: GraphQL JSON POST request building and execution integration.
- `yslfuzz.auth`: environment-variable-based authentication profiles and redaction support.
- `yslfuzz.analysis`: REST and generic response detectors.
- `yslfuzz.analysis.graphql`: GraphQL-specific conservative detectors.
- `yslfuzz.reporting`: redacted JSON reports and minimal Markdown rendering.
- `yslfuzz.evaluation`: ground-truth matching and metric exports.
- `yslfuzz.benchmark`: repeatable benchmark job orchestration.
- `yslfuzz.labs`: local lab manifest loading and validation.
- `yslfuzz.config`: JSON/YAML scan profile loading and CLI merge behavior.
- `yslfuzz.cli`: command-line entry points.

## Data Flow

```text
OpenAPI / GraphQL schema
  -> internal schema model
  -> PayloadCandidate
  -> RequestRecord
  -> ResponseRecord
  -> DetectorResult
  -> SecurityFinding
  -> JSON report / evaluation exports
```

## Safety Boundaries

Generation, execution, analysis, and reporting are separated so risky behavior remains behind
explicit execution gates. Authentication injection happens near execution, and report
serialization applies redaction before output.

## Extension Points

- Add a payload generator by producing `PayloadCandidate` instances and tests.
- Add a detector by returning conservative detector results and findings.
- Add config fields through Pydantic config sections with validation.
- Add CLI flags only when they map cleanly to existing configuration or execution behavior.
