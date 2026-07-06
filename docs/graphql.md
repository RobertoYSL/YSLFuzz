# GraphQL Discovery and Payload Generation

YSLFuzz supports local GraphQL discovery and deterministic valid GraphQL payload generation.
This milestone does not execute GraphQL operations.

## Supported Inputs

Supported local files:

- GraphQL SDL: `.graphql`, `.gql`
- GraphQL introspection JSON: `.json`

No live introspection, remote schema fetching, or HTTP requests are performed while loading schemas.

## Discovery

The discovery layer parses local SDL or introspection JSON into `GraphQLSchema`, then maps root
fields into the internal `ApiSchema` model.

Each GraphQL root field is mapped to an endpoint-like operation:

- synthetic method: `POST`
- synthetic path: `/graphql`
- `api_style`: `GRAPHQL`
- GraphQL arguments become `GRAPHQL_ARGUMENT` parameters
- return type is stored in response metadata

The conservative SDL parser supports object, input, enum, scalar, Query, Mutation and Subscription
definitions, field arguments, list wrappers and non-null wrappers. It is not a complete GraphQL
specification parser.

## Valid Payload Generation

`GraphQLPayloadGenerator` generates safe `PayloadCandidate` objects from a parsed `GraphQLSchema`.
Each candidate body uses the future GraphQL-over-HTTP JSON shape:

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

## Variables and Input Objects

Variables are enabled by default. Operation arguments become variable definitions and variable
bindings. Input objects include required and optional fields within the configured bounds. Nested
input objects and lists are bounded by `max_input_depth` and `max_list_items`.

If `generate_variables` is disabled in code, safe literals are inlined instead.

## Selection Sets

Selection sets are deterministic and bounded:

- scalar and enum fields are selected directly;
- object and list return types receive nested selection sets;
- cycles are avoided;
- fields with required arguments are skipped inside selection sets;
- deprecated fields are skipped when metadata marks them deprecated;
- `__typename` is included only when configured.

Default limits are `max_selection_depth=2` and `max_fields_per_selection=5`.

## CLI Usage

Generate GraphQL discovery and payload summary without HTTP execution:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --dry-run \
  --output graphql_report.json
```

Useful optional flags:

```bash
--graphql-max-selection-depth 2
--graphql-max-fields-per-selection 5
--graphql-queries-only
--graphql-mutations-only
--graphql-max-operations 10
```

The CLI always executes zero GraphQL HTTP requests in this milestone and prints a clear message
that GraphQL execution is planned for Milestone 21.

## Configuration

Configuration profiles can select GraphQL discovery and payload generation:

```json
{
  "target": {
    "api_style": "GRAPHQL",
    "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
    "base_url": "http://localhost:8080"
  },
  "payloads": {
    "graphql_include_queries": true,
    "graphql_include_mutations": true,
    "graphql_include_subscriptions": false,
    "graphql_max_selection_depth": 2,
    "graphql_max_fields_per_selection": 5,
    "graphql_max_operations": 10
  },
  "execution": {
    "dry_run": true
  },
  "reporting": {
    "output": "graphql_report.json"
  }
}
```

Config support is limited to local schema discovery and valid payload generation. It does not enable
GraphQL execution.

## Reporting

JSON reports include safe GraphQL metadata:

- `api_style: graphql`
- `graphql_schema_id`
- generated payload counts by query, mutation and subscription;
- generated operation names;
- configured selection limits;
- `execution_enabled: false`;
- a note that GraphQL execution is not implemented until Milestone 21.

Reports do not include raw authentication material. Query bodies are present as payload bodies in
the internal report model and remain subject to the existing report redaction layer.

## Current Limitations

- No GraphQL HTTP execution until Milestone 21.
- No GraphQL invalid, boundary, mutation or attack payloads until Milestone 22.
- No GraphQL-specific vulnerability analysis until Milestone 23.
- No live introspection over HTTP.
- No remote schema fetching.
- No DoS-style deep query generation, batching probes, aliasing abuse or fragment expansion.
- No authentication-specific GraphQL behavior.
- The built-in SDL parser intentionally supports a conservative subset.
