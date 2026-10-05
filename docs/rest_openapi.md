# REST/OpenAPI Support

YSLFuzz supports REST scans from local OpenAPI YAML or JSON files.

## Discovery

The OpenAPI discovery layer reads local schemas and creates internal endpoint, parameter,
request body, response, and security metadata. It focuses on the subset needed for payload
generation and execution, including paths, methods, parameters, JSON request bodies, and
basic schema constraints.

## Payload Generation

REST payload generation supports:

- `VALID`: schema-aware values intended to satisfy the OpenAPI shape.
- `BOUNDARY`: safe edge values such as empty, short, long-bounded, numeric edge, and list variants.
- `INVALID`: safe type or required-field violations for validation behavior.
- `MUTATED`: bounded semantic variations of valid payloads.
- `ATTACK`: safe attack-classified markers and probes.

Attack-classified payloads are inert and controlled. YSLFuzz does not include operational
exploit strings.

## Execution

The REST execution path builds HTTP requests, applies configured authentication, enforces
scope and safety checks, optionally executes through `httpx`, and records redacted response
records. Dry-run builds planned requests without sending them.

## Stateful Dependency Workflows

Real-world REST APIs often require dynamically created identifiers (e.g. `userId`, `vehicleId`,
`orderId`) before downstream endpoints can be queried or modified.

YSLFuzz includes an automated stateful workflow engine:
1. **Dependency Analysis**: `DependencyGraphAnalyzer` scans the OpenAPI schema to infer producer-consumer
   relationships between endpoints (e.g. a `POST /resource` that returns `id` produces values consumed
   by `GET /resource/{id}`).
2. **Workflow Chaining**: `WorkflowBuilder` constructs executable sequences of dependent requests.
3. **Value Extraction & Binding**: `WorkflowExecutor` executes the setup requests, extracts dynamic
   identifiers from 2xx JSON response bodies, and binds them into downstream path, query, and body
   parameters.

Workflows are enabled by default in the `standard`, `deep`, and `full` presets, or via `--stateful`.

## Oracles and Detection

YSLFuzz implements multi-layered oracles to detect API anomalies and vulnerabilities:

- **Baseline Crash Detector (`BaselineCrashDetector`)**: Analyzes initial compliant requests to
  uncover unhandled `500 Internal Server Error` exceptions. This detects application crashes
  occurring on formally valid inputs.
- **Schema Conformance Detector (`SchemaConformanceDetector`)**: Validates server responses against
  the documented OpenAPI `responses` specification. It flags undocumented status codes and
  undocumented fields in response bodies, effectively identifying **Excessive Data Exposure**
  (OWASP API3:2023) and schema drift.
- **Differential Oracles (`DifferentialResponseDetector`)**: Measures changes in status code,
  body length, and response hash between baseline requests and mutated/attack inputs.
- **Multi-User Authorization Oracles (`BasicAuthorizationBypassDetector`)**: In dual-user mode
  (`--auth-user2-bearer-env`), compares responses when accessing resources across identity boundaries
  to detect Broken Object Level Authorization (BOLA/IDOR).
- **Validation Bypass Detector (`ValidationBypassDetector`)**: Flags 2xx acceptance of inputs
  violating declared type, range, or required constraints.

## Destructive Method Guard

Potentially destructive REST methods are guarded. Execution of `PUT`, `PATCH`, and `DELETE`
requires `--allow-destructive` or the equivalent configuration. Active fuzzing with mutations
or attack probes prompts for interactive confirmation unless `--yes` / `-y` is supplied.

## Limitations

- OpenAPI support is schema-driven and does not implement every vendor-specific OpenAPI extension.
- Complex polymorphism (`oneOf`, `anyOf`) may be approximated to a representative candidate.
- YSLFuzz does not authenticate through interactive OAuth browser flows.
- Findings are conservative signals, which should be reviewed in context.
