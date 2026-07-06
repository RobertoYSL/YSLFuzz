# Benchmarking

The benchmark command runs configured scan jobs and can optionally evaluate each job against
ground truth.

## CLI

```bash
uv run yslfuzz benchmark \
  --config examples/benchmarks/simple_users_benchmark.json \
  --output-dir reports/benchmark \
  --dry-run \
  --overwrite
```

Options:

- `--config`: benchmark JSON/YAML config path.
- `--output-dir`: benchmark output directory.
- `--fail-fast`: stop after the first failed job.
- `--dry-run`: force dry-run mode for every job.
- `--overwrite`: allow writing into an existing output directory.
- `--verbose`: print benchmark job progress.

## Config Format

A benchmark config includes benchmark metadata and one or more jobs. Current job models focus
on REST/OpenAPI benchmark scans:

- job ID and name;
- target name and base URL;
- OpenAPI path;
- optional ground-truth path;
- dry-run and timeout settings;
- payload generation settings;
- mutation and attack execution gates;
- authentication environment references.

## Outputs

Benchmark output includes:

- a manifest;
- summary JSON;
- summary CSV;
- per-job scan report paths;
- optional evaluation output directories;
- reproducibility metadata;
- stability metrics when available in scan reports.

## Dry-Run Defaults

Benchmark jobs default to dry-run unless configured otherwise. The CLI `--dry-run` flag forces
dry-run for all jobs.

## Limitations

- The benchmark harness is not a thesis experiment runner.
- Third-party baseline comparison is outside the core product.
- Current benchmark job models are REST/OpenAPI oriented.
