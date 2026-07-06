# GraphQL Discovery, Payload Generation, and Execution

YSLFuzz supports local GraphQL discovery, deterministic valid payload generation, valid payload
execution, and safe GraphQL boundary, invalid, mutated, and attack-classified payload generation.

## Supported Inputs

Supported local files:

- GraphQL SDL: `.graphql`, `.gql`
- GraphQL introspection JSON: `.json`

Schema loading is local only. YSLFuzz does not perform live introspection, remote schema fetching,
or schema downloads.

## Discovery

The discovery layer parses local SDL or introspection JSON into `GraphQLSchema`, then maps root
fields into the internal `ApiSchema` model.

Each GraphQL root field is mapped to an endpoint-like operation:

- synthetic method: `POST`
- synthetic path: `/graphql`
- `api_style`: `GRAPHQL`
- GraphQL arguments become `GRAPHQL_ARGUMENT` parameters
- return type is stored in response metadata

The SDL parser supports a conservative subset: object, input, enum, scalar, Query, Mutation and
Subscription definitions, field arguments, list wrappers and non-null wrappers.

## Valid Payload Generation

`GraphQLPayloadGenerator` generates safe `PayloadCandidate` objects from a parsed `GraphQLSchema`.
Each candidate body uses the GraphQL-over-HTTP JSON shape:

```json
{
  "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }",
  "variables": {
    "id": "yslfuzz-id-001"
  },
  "operationName": "YSLFuzzUser"
}
```

Generated payloads are `PayloadKind.VALID`, use `content_type="application/json"`, and include
GraphQL metadata such as operation name, operation type, return type, variable names, selection
depth, source schema ID and payload generation version.

## Scalar and Enum Values

Built-in scalar values are deterministic:

- `ID`: `yslfuzz-id-001`
- `String`: `yslfuzz-string`
- `Int`: `1`
- `Float`: `1.0`
- `Boolean`: `true`

Email-like custom scalars use `yslfuzz@example.invalid`. Other custom scalars use the conservative
string `yslfuzz-string`. Enum generation chooses the first allowed enum value deterministically.

No secrets, tokens, cookies, API keys, passwords, JWTs, or real credentials are generated.

## Selection and Variables

Variables are enabled by default. Operation arguments become variable definitions and variable
bindings. Input objects include fields within configured bounds. Nested input objects and lists are
bounded by `max_input_depth` and `max_list_items`.

Selection sets are deterministic and bounded:

- scalar and enum fields are selected directly;
- object and list return types receive nested selection sets;
- cycles are avoided;
- fields with required arguments are skipped inside selection sets;
- deprecated fields are skipped when metadata marks them deprecated;
- `__typename` is included only when configured.

Default limits are `max_selection_depth=2` and `max_fields_per_selection=5`.

## Boundary, Invalid, Mutated, and Attack Payloads

GraphQL non-valid payload generation is disabled by default. It is enabled only with the existing
payload flags:

- `--include-boundary-payloads`
- `--include-invalid-payloads`
- `--include-mutated-payloads`
- `--include-attack-payloads`

Boundary payloads mutate variables with bounded values such as empty strings, whitespace strings,
synthetic ID markers, `0`, `-1`, flipped booleans, alternate enum values, and bounded list sizes.

Invalid payloads create schema-invalid but safe inputs such as null for non-null variables, wrong
scalar type when type-confusion is enabled, invalid enum values only when explicitly allowed, extra
input object fields, and missing required input object fields.

Mutated payloads are safe semantic variations such as alternate scalar values, alternate enum
values, and bounded variable variation. They are not vulnerability probes by themselves.

Attack-classified payloads use inert markers only:

- `INPUT_VALIDATION`: safe invalid variable values.
- `INFORMATION_DISCLOSURE`: safe schema validation error probes.
- `XSS`: inert reflection marker `yslfuzz_graphql_reflection_marker`; no executable JavaScript.
- `MASS_ASSIGNMENT`: safe extra input field `yslfuzz_extra_field`.
- `SQL_INJECTION`: inert marker `yslfuzz_graphql_sql_marker`; no SQL syntax.
- `NOSQL_INJECTION`: inert marker `yslfuzz_graphql_nosql_marker`; no NoSQL operator objects.
- `COMMAND_INJECTION`: inert marker `yslfuzz_graphql_command_marker`; no shell syntax or command names.
- `SSRF`: inert marker `https://yslfuzz-ssrf-marker.invalid/resource`; no localhost, private IP,
  link-local, cloud metadata, or callback targets.
- `GRAPHQL_INTROSPECTION_ABUSE`: minimal `__schema` query only when introspection probe generation is explicitly enabled.

No auth bypass payloads are generated in this milestone. No credentials are changed or removed.
Broken access control is represented by metadata-compatible analysis support for explicitly paired
records only.

## Execution

GraphQL execution uses a POST request to the configured GraphQL endpoint path. The default endpoint
path is `/graphql`.

Request headers include:

- `Content-Type: application/json`
- `Accept: application/json`

The request body contains `query`, `variables`, and `operationName` when present. Authentication
profiles are applied through the same auth resolver and injector used by REST execution.

Dry-run mode builds planned GraphQL request records but executes zero HTTP requests. Non-dry-run
mode executes valid GraphQL payloads through the shared `HttpExecutor`.

Boundary, invalid and mutated GraphQL payloads execute only when `--execute-mutations` is set with
`--i-understand-mutation-execution-is-authorized`. Attack-classified GraphQL payloads execute only
when `--execute-attacks` is set with `--i-understand-this-is-authorized`. These gates are separate:
`--execute-mutations` does not imply `--execute-attacks`, and `--execute-attacks` does not imply
`--execute-mutations`.

GraphQL HTTP 200 responses with an `errors` array are captured as response metadata:

- `graphql_has_errors`
- `graphql_error_count`

## GraphQL Analysis

GraphQL-specific analysis runs on executed GraphQL response records through the shared analysis
engine. It is conservative and produces LOW or MEDIUM severity findings only.

Implemented GraphQL detectors:

- `GraphQLErrorDisclosureDetector`: GraphQL `errors` arrays with stack-trace-like, framework,
  resolver, database, or internal extension details.
- `GraphQLValidationBypassDetector`: invalid or boundary GraphQL payloads that receive HTTP 2xx
  responses with `data` and no GraphQL errors.
- `GraphQLIntrospectionExposureDetector`: schema metadata only from already executed introspection
  probes.
- `GraphQLReflectionDetector`: exact reflection of YSLFuzz inert markers.
- `GraphQLMassAssignmentDetector`: successful handling of the safe extra input field marker.
- `GraphQLAuthorizationConsistencyDetector`: explicitly paired authenticated and unauthenticated
  or alternate-profile records. It does not mutate credentials or remove auth silently.
- `GraphQLInjectionMarkerDetector`: inert SQL, NoSQL, and command marker response signals without
  real exploit strings.
- `GraphQLSSRFMarkerDetector`: URL-handling signals for the safe `.invalid` SSRF marker without
  network callbacks or internal targets.

Findings are intentionally phrased as "Possible" signals. YSLFuzz does not confirm GraphQL
vulnerabilities in this milestone.

## CLI Usage

Dry-run planning:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --dry-run \
  --output graphql_report.json
```

Execution against an authorized local GraphQL endpoint:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --graphql-endpoint /graphql \
  --graphql-max-requests 20 \
  --output graphql_report.json
```

Useful optional flags:

```bash
--graphql-endpoint /graphql
--graphql-max-requests 20
--graphql-max-selection-depth 2
--graphql-max-fields-per-selection 5
--graphql-queries-only
--graphql-mutations-only
--graphql-max-operations 10
--graphql-include-introspection-probe
--max-requests 50
--graphql-max-requests 25
--max-requests-per-endpoint 10
--rate-limit-rps 2.0
```

Generate boundary payloads in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-boundary-payloads \
  --dry-run \
  --output graphql_boundary_report.json
```

Generate invalid payloads in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-invalid-payloads \
  --dry-run \
  --output graphql_invalid_report.json
```

Generate inert attack-classified probes in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --dry-run \
  --output graphql_attack_generation_report.json
```

Generate safe SQL marker probes in dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --attack-category SQL_INJECTION \
  --dry-run \
  --output graphql_sql_marker_report.json
```

Generate the bounded introspection probe only when explicitly enabled:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --attack-category GRAPHQL_INTROSPECTION_ABUSE \
  --graphql-include-introspection-probe \
  --dry-run \
  --output graphql_introspection_probe_report.json
```

Execute GraphQL mutated payloads only with explicit authorization:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-mutated-payloads \
  --execute-mutations \
  --i-understand-mutation-execution-is-authorized \
  --output graphql_mutation_exec_report.json
```

Execute GraphQL attack-classified probes only with explicit authorization:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --include-attack-payloads \
  --execute-attacks \
  --i-understand-this-is-authorized \
  --output graphql_attack_exec_report.json
```

`--openapi` and `--graphql-schema` remain mutually exclusive.

## Configuration

Configuration profiles can select GraphQL discovery, payload generation, and execution settings:

```json
{
  "target": {
    "api_style": "GRAPHQL",
    "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
    "base_url": "http://localhost:8080"
  },
  "graphql": {
    "endpoint_path": "/graphql",
    "max_selection_depth": 2,
    "max_fields_per_selection": 5,
    "include_queries": true,
    "include_mutations": true,
    "max_requests": 20,
    "enable_analysis": true,
    "include_introspection_probe": false
  },
  "execution": {
    "dry_run": true,
    "execute_mutations": false,
    "execute_attacks": false,
    "timeout": 5,
    "max_requests": 50
  },
  "payloads": {
    "include_boundary_payloads": true,
    "include_invalid_payloads": true,
    "include_mutated_payloads": false,
    "include_attack_payloads": false,
    "max_mutations_per_payload": 10,
    "max_mutations_per_field": 3,
    "allow_invalid_enum_values": false,
    "mutate_sensitive_fields": false,
    "enabled_attack_categories": [
      "INPUT_VALIDATION",
      "INFORMATION_DISCLOSURE",
      "SQL_INJECTION",
      "NOSQL_INJECTION",
      "COMMAND_INJECTION",
      "SSRF"
    ]
  },
  "analysis": {
    "enable_graphql_error_disclosure": true,
    "enable_graphql_validation_bypass": true,
    "enable_graphql_introspection_exposure": true,
    "enable_graphql_reflection_detection": true,
    "enable_graphql_mass_assignment_detection": true,
    "enable_graphql_authorization_consistency": true,
    "enable_graphql_injection_marker_detection": true,
    "enable_graphql_ssrf_marker_detection": true
  },
  "reporting": {
    "output": "graphql_report.json"
  }
}
```

`execution.dry_run` always prevents HTTP execution. If both `graphql.max_requests` and
`execution.max_requests` are set, the stricter request limit is used.

Config-driven mutation execution still requires
`i_understand_mutation_execution_is_authorized=true`. Config-driven attack execution still requires
`i_understand_attack_execution_is_authorized=true`.

## Authentication

Authentication profiles work with GraphQL execution:

- bearer token env var becomes an `Authorization` header;
- API key env var becomes the configured API key header;
- cookie auth becomes a `Cookie` header;
- custom auth header env vars become their configured headers.

Config files and CLI arguments must reference environment variable names only. Raw auth values are
redacted in request records, reports, summaries, and serialized models.

## Reporting

JSON reports include safe GraphQL metadata:

- `api_style: graphql`
- `graphql_schema_id`
- generated payload counts by query, mutation and subscription;
- generated operation names;
- configured selection limits;
- `graphql_endpoint_path`;
- GraphQL requests planned, executed, and skipped by dry-run;
- GraphQL responses received;
- transport error count;
- GraphQL application error count from response `errors` arrays;
- stability summary fields such as request budgets, retry counts, timeout state and skipped counts;
- boundary, invalid, mutated, and attack payload counts;
- mutation operator counts;
- attack categories generated;
- inert markers used;
- safe SQL, NoSQL, command, and SSRF marker payload counts;
- GraphQL analysis findings by detector, category, and severity;
- skipped dry-run and skipped not-authorized counts;
- `execution_enabled`;
- `dry_run`.

Reports do not include raw authentication material.

## Current Limitations

- No vulnerability confirmation or overclaiming based on generated probes.
- No active authz probe execution flags yet.
- No batching.
- No subscriptions or WebSocket execution.
- No live introspection over HTTP.
- No remote schema fetching.
- No multipart upload.
- No GET-based GraphQL execution.
- No DoS-style deep query generation, aliasing abuse or fragment expansion.
- No real SQL injection, NoSQL injection, command execution, SSRF, cloud metadata, internal IP,
  executable JavaScript, credential stuffing, or auth bypass payload strings.
- The built-in SDL parser intentionally supports a conservative subset.
