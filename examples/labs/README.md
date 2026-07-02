# YSLFuzz Lab Packs

Lab packs are local metadata bundles for reproducible YSLFuzz evaluation and benchmarking. A lab pack describes a target, its OpenAPI schema, expected vulnerabilities, safe benchmark defaults, setup notes, and limitations.

Available MVP lab packs:

- `simple-users`: deterministic mock REST/OpenAPI lab metadata for local dry-run evaluation and benchmark smoke tests.

Future lab pack candidates:

- OWASP crAPI
- OWASP Juice Shop
- Damn Vulnerable REST API or similar vulnerable REST API labs

These future candidates are documentation-only for now. This repository does not bundle third-party vulnerable applications, Docker orchestration, automatic downloads, credentials, or external executable targets. Run vulnerable labs only in authorized local environments.
