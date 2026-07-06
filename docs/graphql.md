# GraphQL Discovery, Payload Generation, and Execution

YSLFuzz supports local GraphQL discovery, deterministic valid GraphQL payload generation, and safe
HTTP execution of valid GraphQL operation payloads.

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

## Execution

GraphQL execution uses a POST request to the configured GraphQL endpoint path. The default endpoint
path is `/graphql`.

Request headers include:

- `Content-Type: application/json`
- `Accept: application/json`

The request body contains `query`, `variables`, and `operationName` when present. Authentication
profiles are applied through the same auth resolver and injector used by REST execution.

Dry-run mode builds planned GraphQL request records but executes zero HTTP requests. Non-dry-run
mode executes only valid GraphQL payloads through the shared `HttpExecutor`.

GraphQL HTTP 200 responses with an `errors` array are captured as response metadata:

- `graphql_has_errors`
- `graphql_error_count`

These errors are not classified as vulnerabilities in this milestone.

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
    "max_requests": 20
  },
  "execution": {
    "dry_run": true,
    "timeout": 5,
    "max_requests": 50
  },
  "reporting": {
    "output": "graphql_report.json"
  }
}
```

`execution.dry_run` always prevents HTTP execution. If both `graphql.max_requests` and
`execution.max_requests` are set, the stricter request limit is used.

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
- `execution_enabled`;
- `dry_run`.

Reports do not include raw authentication material.

## Current Limitations

- No GraphQL invalid, boundary, mutation or attack payloads until Milestone 22.
- No GraphQL-specific vulnerability analysis until Milestone 23.
- No batching.
- No subscriptions or WebSocket execution.
- No live introspection over HTTP.
- No remote schema fetching.
- No multipart upload.
- No GET-based GraphQL execution.
- No DoS-style deep query generation, aliasing abuse or fragment expansion.
- The built-in SDL parser intentionally supports a conservative subset.
