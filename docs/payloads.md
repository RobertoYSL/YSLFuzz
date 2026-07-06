# Payloads

YSLFuzz represents generated inputs as `PayloadCandidate` objects. A candidate includes an
endpoint ID, payload kind, content type, body, parameters, headers, cookies, generation
strategy, seed, optional attack category, and optional `parent_payload_id`.

## Payload Kinds

- `VALID`: schema-aware payloads intended to be accepted.
- `BOUNDARY`: safe edge-case values within bounded limits.
- `INVALID`: safe invalid-input payloads for validation behavior.
- `MUTATED`: bounded variations derived from valid payloads.
- `ATTACK`: safe attack-classified probes with inert markers only.

## Lineage

Non-valid payloads preserve lineage through `parent_payload_id` when derived from a valid
payload. GraphQL payload metadata also records operation type, operation name, target
variable, mutation operator, and safety labels where applicable.

## Determinism

Payload generation is deterministic by default. Seeds and generation strategies are recorded
so repeated runs with the same schema and config produce stable output.

## Sensitive Fields

Sensitive fields are skipped by default for mutation-style generation where metadata is
available. Authentication material is never generated as payload data. Reports redact
sensitive headers, cookies, and body values through the reporting layer.

## REST Payloads

REST payloads are generated from OpenAPI endpoint parameters and request body schemas.
Boundary, invalid, mutated, and attack modes are disabled unless requested.

## GraphQL Payloads

GraphQL valid payloads contain JSON bodies shaped like:

```json
{
  "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id email } }",
  "variables": {
    "id": "yslfuzz-id-001"
  },
  "operationName": "YSLFuzzUser"
}
```

GraphQL non-valid payloads derive from valid payloads and mutate variables, selection sets,
or safe marker values within configured limits.

## Safe Markers

Attack-classified probes use inert marker values such as `yslfuzz_graphql_sql_marker` and
`yslfuzz_graphql_reflection_marker`. SSRF category coverage uses a reserved `.invalid`
marker URL only. These are analysis signals, not exploit payloads.

## Limits

Payload generation is bounded by per-payload mutation limits, per-field mutation limits,
GraphQL operation limits, selection depth limits, field count limits, and scan-level request
budgets.
