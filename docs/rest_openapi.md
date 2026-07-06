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

## Stateful Workflows

The execution layer contains workflow support for stateful scan scenarios. Current examples
focus on small local schemas and conservative request budgets.

## Destructive Method Guard

Potentially destructive REST methods are guarded. Execution of `PUT`, `PATCH`, and `DELETE`
requires `--allow-destructive` or the equivalent configuration. Mutation and attack payload
execution require their own explicit gates as well.

## Limitations

- OpenAPI support is schema-driven and does not implement every OpenAPI extension.
- Complex polymorphism and vendor-specific behavior may be approximated.
- YSLFuzz does not authenticate through OAuth browser flows.
- Findings are conservative signals, not proof of a vulnerability.
