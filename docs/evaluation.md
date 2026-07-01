# YSLFuzz Evaluation

YSLFuzz can compare an existing JSON scan report with a ground-truth lab file and export benchmark-friendly JSON and CSV artifacts. Evaluation is offline only: it reads existing files and does not run scans or contact targets.

## Ground-Truth Format

Ground truth can be JSON or YAML. Required top-level fields:

- `lab_id`
- `lab_name`
- `lab_version`
- `target_name`
- `target_base_url`
- `api_style`
- `expected_vulnerabilities`
- `expected_endpoints`

Each expected vulnerability includes:

- `ground_truth_id`
- `endpoint_path`
- `endpoint_method`
- `attack_category`
- `vulnerability_type`
- `expected_severity`
- `affected_parameter`
- `affected_location`
- `cwe`
- `owasp_api_category`
- `description`
- `tags`

See `examples/evaluation/simple_users_ground_truth.json` for a minimal mock-lab example.

## Running Evaluation

```bash
yslfuzz evaluate \
  --report yslfuzz_report.json \
  --ground-truth examples/evaluation/simple_users_ground_truth.json \
  --output-dir evaluation_results/
```

The command writes:

- `evaluation.json`
- `findings.csv`
- `endpoints.csv`
- `matches.csv`
- `metrics.csv`

## Matching

Matching is deterministic and conservative. A finding matches ground truth when endpoint path, endpoint method, and attack category match. If both the finding and ground-truth item provide an affected parameter, the parameter must also match.

No fuzzy matching, machine learning, timestamps, request IDs, or response IDs are used for matching.

## Metrics

- `precision = TP / (TP + FP)`, or `0` if the denominator is `0`
- `recall = TP / (TP + FN)`, or `0` if the denominator is `0`
- `f1_score = 2 * precision * recall / (precision + recall)`, or `0` if the denominator is `0`
- `endpoint_coverage` is copied from the YSLFuzz report metrics when available.
- `payload_validity_rate` is copied from the YSLFuzz report metrics when available.

## Limitations

- Evaluation does not run third-party scanners.
- Evaluation does not deploy or manage vulnerable labs.
- GraphQL-specific benchmark matching is not implemented in this MVP.
- Matching is intentionally field-based and conservative; manual review is still required for thesis conclusions.
- Outputs are redacted with the same report redaction helper used by JSON reporting.
