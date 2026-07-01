# YSLFuzz Benchmarking

The benchmark harness runs one or more declarative YSLFuzz scan/evaluation jobs and writes a deterministic result bundle. It is intended for thesis-style experiments where each run should be reproducible and easy to compare.

## Usage

```bash
yslfuzz benchmark \
  --config examples/benchmarks/simple_users_benchmark.json \
  --output-dir benchmark_results/simple_users_run_01
```

Useful options:

- `--fail-fast`: stop after the first failed job.
- `--dry-run`: force dry-run mode for all jobs.
- `--overwrite`: allow writing into an existing output directory.
- `--verbose`: print job-level progress.

## Safe Defaults

Benchmark job defaults are conservative:

- `dry_run = true`
- `allow_destructive = false`
- `execute_attacks = false`
- `execute_mutations = false`
- attack, mutation, boundary, invalid, and mutated payload generation are disabled unless explicitly enabled.

If a job sets `execute_attacks = true`, it must also set `i_understand_attack_execution_is_authorized = true`.

If a job sets `execute_mutations = true`, it must also set `i_understand_mutation_execution_is_authorized = true`.

## Config Format

Top-level benchmark fields:

- `benchmark_id`
- `benchmark_name`
- `benchmark_version`
- `description`
- `random_seed`
- `output_naming_strategy`
- `jobs`

Each job supports:

- `job_id`
- `job_name`
- `target_name`
- `base_url`
- `openapi_path`
- `ground_truth_path`
- `output_subdir`
- `max_requests`
- `timeout`
- `dry_run`
- `allow_destructive`
- `include_boundary_payloads`
- `include_invalid_payloads`
- `include_mutated_payloads`
- `include_attack_payloads`
- `execute_mutations`
- `execute_attacks`
- `enabled_attack_categories`
- `max_mutations_per_payload`
- `max_mutations_per_field`
- `max_attack_requests_per_endpoint`
- `notes`
- `metadata`

JSON is the required MVP format. YAML also works because the project already depends on PyYAML.

## Output Structure

```text
output-dir/
├── benchmark_manifest.json
├── benchmark_summary.json
├── benchmark_summary.csv
└── jobs/
    └── <job_id>/
        ├── scan_report.json
        ├── evaluation/
        │   ├── evaluation_report.json
        │   ├── evaluation.json
        │   ├── findings.csv
        │   ├── endpoints.csv
        │   ├── matches.csv
        │   └── metrics.csv
        └── job_metadata.json
```

If a job has no `ground_truth_path`, the `evaluation/` directory is omitted and `job_metadata.json` records only scan metrics.

## Manifest

`benchmark_manifest.json` includes:

- benchmark identity and version;
- YSLFuzz version;
- started and finished timestamps;
- random seed;
- deterministic config hash;
- job results;
- artifact list;
- environment summary containing Python version, platform, and YSLFuzz version.

No environment variables or secrets are included.

## Thesis Evaluation

`benchmark_summary.csv` is designed for thesis tables. It includes request, payload, finding, and evaluation metrics for every job. More detailed per-finding, per-endpoint, and per-match CSV files are written inside each job's `evaluation/` directory when ground truth is available.

## Limitations

- The harness does not run third-party tools.
- The harness does not manage Docker Compose labs.
- No repeated campaign scheduler or statistical analysis is implemented.
- Tests and example configs use dry-run/local files only.
