# GraphQL

YSLFuzz supports local GraphQL schema discovery, payload generation, execution, safe marker
probes, and conservative GraphQL-specific analysis.

## Schema Inputs

Supported inputs:

- SDL files such as `examples/graphql/simple_users_schema.graphql`.
- Local introspection JSON files such as `examples/graphql/simple_users_introspection.json`.
- Live remote GraphQL endpoints via HTTP/HTTPS URL (e.g. `http://localhost:5013/graphql`), where YSLFuzz executes a standard introspection query.

## Discovery

GraphQL discovery parses the schema (from local file or remote endpoint) and builds internal metadata for operation roots,
fields, arguments, input objects, enums, scalar types, and schema identifiers. Discovery
results feed payload generation and reporting.

## Valid Payload Generation

Valid GraphQL payloads are deterministic and schema-aware. The generated HTTP body shape is:

```json
{
  "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }",
  "variables": {
    "id": "yslfuzz-id-001"
  },
  "operationName": "YSLFuzzUser"
}
```

Default scalar values:

- `ID`: `yslfuzz-id-001`
- `String`: `yslfuzz-string`
- `Int`: `1`
- `Float`: `1.0`
- `Boolean`: `true`

Enums choose a deterministic allowed value. Input objects generate required fields and
bounded optional fields. Lists use configured item limits.

## Selection Sets

Selection sets are bounded by:

- maximum selection depth;
- maximum fields per selection;
- cycle detection;
- deprecated field filtering unless enabled.

`__typename` is optional and not included by default.

## Execution

GraphQL execution uses HTTP JSON POST requests to `--graphql-endpoint`, defaulting to
`/graphql`. The request includes `Content-Type: application/json` and `Accept: application/json`.
Dry-run builds planned requests and sends nothing.

Example dry-run:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8000 \
  --graphql-endpoint /graphql \
  --dry-run \
  --output reports/graphql_dry_run.json
```

## Boundary, Invalid, Mutated, and Attack Payloads

GraphQL non-valid payloads derive from valid payloads and preserve lineage through
`parent_payload_id`. Generation is configured directly or via scan presets:
- `--preset quick`: executes valid baseline GraphQL operations.
- `--preset deep` / `--preset full`: enables boundary edge cases, variable mutations, safe attack-classified probes, and advanced oracles.
- Interactive safety prompt protects active fuzzing unless `-y` / `--yes` is supplied.

## Safe Attack-Classified Probes

GraphQL attack-classified probes use inert YSLFuzz markers only. Category coverage includes
input validation, information disclosure, reflection, mass assignment, broken access control
metadata support, SQL boolean differential probes, NoSQL marker handling, command marker handling, and
SSRF marker handling.

Introspection probes are disabled by default and require explicit opt-in with
`--graphql-include-introspection-probe` or matching configuration.

## GraphQL Analysis and Advanced Oracles

GraphQL analysis is signal-based and includes specialized oracles:

- **Field Suggestion Leakage (`GraphQLFieldSuggestionDetector`)**: Sends controlled typographical
  errors in field and operation names to test whether the GraphQL engine leaks internal schema
  structure via "Did you mean..." suggestions when introspection is disabled.
- **Boolean SQL Injection Differential Oracle (`GraphQLBooleanSqlInjectionDetector`)**: In GraphQL,
  SQL injections on queries often do not crash or return HTTP 500, but return HTTP 200 OK while
  expanding the result set. This oracle injects an inert boolean condition (`' OR 'yslfuzz_probe'='yslfuzz_probe`)
  and compares the cardinality of records returned in `data.<field>` against the baseline response.
- **Pagination Limit Control (`--graphql-pagination-limit`)**: Allows setting collection query
  limits (default: 50) so differential record expansion can be observed reliably.
- **Error Disclosure (`GraphQLErrorDisclosureDetector`)**: Flags verbose internal server errors,
  stack traces, or database dialect identifiers in GraphQL response errors.
- **Validation Bypass (`GraphQLValidationBypassDetector`)**: Flags successful responses to invalid
  scalar types or missing required non-null arguments.
- **Marker Reflection (`GraphQLReflectionDetector`)**: Flags reflection of inert fuzzing probes.

## Configuration

```yaml
target:
  api_style: graphql
  graphql_schema_path: examples/graphql/simple_users_schema.graphql
  base_url: http://localhost:8000

graphql:
  endpoint_path: /graphql
  max_selection_depth: 2
  max_fields_per_selection: 5
  include_queries: true
  include_mutations: true
  include_introspection_probe: false
  pagination_limit: 50

execution:
  dry_run: true
```

## Limits and Prohibitions

Current GraphQL support intentionally does not include:

- DoS-style deep recursive queries;
- alias or fragment explosion;
- batching abuse;
- subscriptions / WebSocket execution;
- multipart upload;
- GET-based GraphQL execution;
- operational SQL/OS injection exploit payloads.
