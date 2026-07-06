# GraphQL

YSLFuzz supports local GraphQL schema discovery, payload generation, execution, safe marker
probes, and conservative GraphQL-specific analysis.

## Schema Inputs

Supported inputs:

- SDL files such as `examples/graphql/simple_users_schema.graphql`.
- Local introspection JSON files such as `examples/graphql/simple_users_introspection.json`.

YSLFuzz does not perform live remote introspection as a discovery step.

## Discovery

GraphQL discovery parses the local schema and builds internal metadata for operation roots,
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
`parent_payload_id`. Generation is disabled unless requested with payload flags such as
`--include-boundary-payloads`, `--include-invalid-payloads`, `--include-mutated-payloads`, or
`--include-attack-payloads`.

Execution gates are unchanged:

- mutation payload execution requires mutation authorization flags;
- attack payload execution requires attack authorization flags;
- dry-run prevents all execution.

## Safe Attack-Classified Probes

GraphQL attack-classified probes use inert YSLFuzz markers only. Category coverage includes
input validation, information disclosure, reflection, mass assignment, broken access control
metadata support, SQL marker handling, NoSQL marker handling, command marker handling, and
SSRF marker handling.

The SQL, NoSQL, command, and SSRF categories are marker-based. YSLFuzz does not generate real
injection strings, command execution payloads, internal network probes, or cloud metadata
probes.

Introspection probes are disabled by default and require explicit opt-in with
`--graphql-include-introspection-probe` or matching configuration.

## GraphQL Analysis

GraphQL analysis is conservative and signal-based. Detectors include:

- possible GraphQL error disclosure;
- possible validation bypass;
- possible introspection exposure from already executed probes;
- inert marker reflection;
- possible mass assignment signal;
- authorization consistency signal when paired metadata exists;
- inert injection marker signal;
- inert SSRF marker signal.

Findings are low or medium confidence signals unless strong deterministic evidence exists.
They are not proof of confirmed vulnerabilities.

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

execution:
  dry_run: true
```

## Limits and Prohibitions

Current GraphQL support does not include:

- DoS-style deep queries;
- alias or fragment explosion;
- batching abuse;
- subscriptions;
- WebSocket execution;
- multipart upload;
- GET-based GraphQL execution;
- live remote introspection discovery;
- authentication bypass testing;
- credential mutation.
