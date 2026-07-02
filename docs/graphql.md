# GraphQL Discovery

YSLFuzz currently supports a GraphQL Discovery MVP. It can parse local GraphQL schema files and local introspection JSON files, extract operations and type information, and map those operations into the internal `ApiSchema` model.

This milestone does not execute GraphQL operations.

## Supported Inputs

Supported local files:

- GraphQL SDL: `.graphql`, `.gql`
- GraphQL introspection JSON: `.json`

No live introspection, remote schema fetching, or HTTP requests are performed.

## SDL Subset

The built-in SDL parser is conservative because no GraphQL parser dependency is currently configured in the project. It supports:

- `type` definitions
- `input` definitions
- `enum` definitions
- `scalar` names
- `Query`, `Mutation`, and `Subscription` root operation types
- field arguments
- list wrappers
- non-null wrappers
- comments
- directives ignored during parsing

It is not a full GraphQL specification parser. Advanced SDL features such as unions, interfaces, schema definition blocks, extensions, fragments, executable documents, and complex directive semantics are not supported in this milestone.

## Introspection JSON Subset

The introspection parser supports a minimal standard structure containing:

- `__schema`
- `types`
- `queryType`
- `mutationType`
- `subscriptionType` when present

The parser accepts either `{"__schema": ...}` or `{"data": {"__schema": ...}}`.

## CLI

Run GraphQL discovery and write a discovery report:

```bash
uv run yslfuzz scan \
  --graphql-schema examples/graphql/simple_users_schema.graphql \
  --base-url http://localhost:8080 \
  --output graphql_report.json
```

OpenAPI and GraphQL inputs are mutually exclusive:

```bash
uv run yslfuzz scan --openapi openapi.yaml --graphql-schema schema.graphql
```

The command above is rejected.

## Configuration

Configuration profiles can select GraphQL discovery:

```json
{
  "target": {
    "api_style": "GRAPHQL",
    "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
    "base_url": "http://localhost:8080"
  },
  "execution": {
    "dry_run": true
  },
  "reporting": {
    "output": "graphql_report.json"
  }
}
```

GraphQL config support only loads and reports schema discovery. It does not enable GraphQL payload generation or execution.

## ApiSchema Mapping

Each GraphQL root field is mapped to an endpoint-like operation:

- synthetic method: `POST`
- synthetic path: `/graphql`
- `api_style`: `GRAPHQL`
- GraphQL arguments become `GRAPHQL_ARGUMENT` parameters
- return type is stored in response metadata
- operation metadata includes:
  - `graphql_operation_name`
  - `graphql_operation_type`
  - `graphql_return_type`
  - `graphql_arguments`
  - `graphql_source_format`
  - `graphql_schema_id`

Reports include GraphQL discovery summaries with operation counts, type counts, and an operation list. Full raw schemas are not embedded in reports.

## Not Supported Yet

The following are intentionally out of scope for this milestone:

- GraphQL payload generation
- GraphQL request execution
- GraphQL mutation payloads
- GraphQL attack payloads
- GraphQL-specific vulnerability analysis
- depth-limit probes
- batching probes
- DoS-style probes
- live introspection over HTTP
- remote schema fetching

## Roadmap

Planned next GraphQL milestones:

- Milestone 20: GraphQL Payload Generation MVP
- Milestone 21: GraphQL Execution MVP
- Milestone 22: GraphQL Mutation and Attack Payload MVP
- Milestone 23: GraphQL Analysis MVP
