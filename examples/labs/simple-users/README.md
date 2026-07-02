# Simple Users Mock Lab

`simple-users` is a minimal REST/OpenAPI lab pack for local YSLFuzz evaluation and benchmark smoke tests.

Files:

- `lab_manifest.json`: lab metadata and safe defaults.
- `openapi.yaml`: local example OpenAPI 3.x schema.
- `ground_truth.json`: expected mock signal used by deterministic evaluation tests.
- `benchmark.json`: dry-run benchmark config with attack and mutation execution disabled.

This pack does not include a runnable vulnerable application. The ground truth uses conservative mock wording and should not be treated as evidence that a real service is vulnerable.

Useful commands from the repository root:

```bash
yslfuzz labs show --lab simple-users
yslfuzz benchmark --config examples/labs/simple-users/benchmark.json --output-dir benchmark_results/simple_users_lab
```

Only run vulnerable targets in local environments where you have explicit authorization.
