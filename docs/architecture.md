# Architecture

YSLFuzz is organized as a set of small layers around shared Pydantic models.

## Layers

- `yslfuzz.discovery`: REST/OpenAPI discovery and schema normalization.
- `yslfuzz.discovery.graphql`: GraphQL SDL, local introspection JSON, and live remote schema loading.
- `yslfuzz.dependency`: Endpoint producer-consumer dependency graph analysis and stateful workflow builder.
- `yslfuzz.payloads`: REST valid, boundary, invalid, mutated, and attack payload generation.
- `yslfuzz.payloads.graphql`: GraphQL operation, variable, selection, mutation, and safe marker generation.
- `yslfuzz.execution`: HTTP request building, execution engine, stateful `WorkflowExecutor`, rate limiting, and stability controls.
- `yslfuzz.execution.graphql`: GraphQL JSON POST request building and execution integration.
- `yslfuzz.auth`: Static auth profiles, dynamic pre-scan login lifecycle, multi-user identity switching, and redaction.
- `yslfuzz.analysis`: Multi-layered oracles (BaselineCrashDetector, SchemaConformanceDetector, DifferentialResponseDetector, BasicAuthorizationBypassDetector).
- `yslfuzz.analysis.graphql`: GraphQL-specific oracles (GraphQLFieldSuggestionDetector, GraphQLBooleanSqlInjectionDetector, error disclosure).
- `yslfuzz.reporting`: Redacted JSON reports, executive Markdown rendering (`--markdown`), and terminal summary table.
- `yslfuzz.evaluation`: Ground-truth matching (`FindingMatcher`) and metric calculation/exports.
- `yslfuzz.benchmark`: Repeatable benchmark job orchestration.
- `yslfuzz.labs`: Local lab manifest loading and validation.
- `yslfuzz.config`: JSON/YAML scan profile loading and CLI merge behavior.
- `yslfuzz.cli.commands`: Modular CLI controllers (`scan.py`, `evaluate.py`, `benchmark.py`, `labs.py`, `graphql.py`).

## Data Flow

```text
OpenAPI / GraphQL schema
  -> internal schema model
  -> dependency graph & stateful workflows
  -> PayloadCandidate
  -> RequestRecord (with auth lifecycle injection)
  -> ResponseRecord
  -> DetectorResult (crash, conformance, differential, BOLA oracles)
  -> SecurityFinding
  -> Redacted JSON report / Executive Markdown / Evaluation exports
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
