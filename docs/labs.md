# YSLFuzz Lab Packs

A lab pack is a local, declarative bundle that connects a target description with the files needed for reproducible YSLFuzz evaluation and benchmarking. Lab commands list and inspect metadata only; they do not scan targets, run benchmarks, download software, or make network calls.

## Directory Structure

```text
examples/labs/
+-- simple-users/
|   +-- lab_manifest.json
|   +-- openapi.yaml
|   +-- ground_truth.json
|   +-- benchmark.json
|   +-- README.md
+-- README.md
```

## Manifest Fields

`lab_manifest.json` includes:

- `lab_id`, `lab_name`, `lab_version`, `description`
- `target_name`, `target_type`, `api_style`
- `openapi_path`, `ground_truth_path`, `benchmark_config_path`
- `recommended_base_url`, `setup_type`, `requires_authentication`
- `required_authentication_types`
- `supported_payload_modes`
- `expected_vulnerability_count`, `expected_endpoint_count`
- `safety_notes`, `limitations`, `tags`, `metadata`

Manifest file paths are local relative paths. Absolute paths, URL paths, and parent-directory escapes are rejected.

If a lab requires authentication, `required_authentication_types` may document safe type names such as `bearer`, `api_key_header`, `cookie`, or `custom_header`. Lab manifests must not include credential values, tokens, cookies, API keys, passwords, or JWTs.

## Ground Truth

`ground_truth.json` follows the existing YSLFuzz evaluation format. Each expected vulnerability has a unique `ground_truth_id`, endpoint method and path, attack category, expected severity, description, and optional affected parameter metadata.

## Benchmark Config

`benchmark.json` follows the existing YSLFuzz benchmark format. Safe lab benchmark configs should keep:

- `dry_run: true`
- `allow_destructive: false`
- `execute_attacks: false`
- `execute_mutations: false`

The `simple-users` config enables payload generation modes for benchmark visibility but does not execute attack or mutation payloads.

## Listing Labs

```bash
yslfuzz labs list
yslfuzz labs show --lab simple-users
```

These commands inspect local metadata only.

## Running A Lab Benchmark

From the repository root:

```bash
yslfuzz benchmark \
  --config examples/labs/simple-users/benchmark.json \
  --output-dir benchmark_results/simple_users_lab
```

The MVP benchmark runner does not provision lab services. Use dry-run or authorized local/mock targets.

## Adding Future Lab Packs

Future real lab candidates include OWASP crAPI, OWASP Juice Shop, and Damn Vulnerable REST API style labs. Do not bundle third-party vulnerable applications, credentials, automatic downloads, Docker orchestration, or external executable defaults in lab packs unless a future milestone explicitly implements and tests that behavior.

## Limitations

- Lab packs are declarative metadata bundles.
- GraphQL lab support is not implemented in this MVP.
- The lab CLI does not run scans or benchmarks.
- Vulnerable labs must only be run in authorized local environments.
- Manual review remains required for thesis conclusions.
