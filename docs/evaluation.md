# Evaluation

YSLFuzz can compare an existing JSON scan report with a JSON or YAML ground-truth file.
Evaluation is useful for local labs and repeatable research review.

## CLI

```bash
uv run yslfuzz evaluate \
  --report reports/scan.json \
  --ground-truth examples/evaluation/simple_users_ground_truth.json \
  --output-dir reports/evaluation
```

## Ground-Truth Format

A ground-truth file describes a lab target and expected vulnerabilities:

```json
{
  "lab_id": "simple-users",
  "lab_name": "Simple Users",
  "lab_version": "1.0.0",
  "target_name": "Simple Users API",
  "target_base_url": "http://localhost:8000",
  "api_style": "rest",
  "expected_endpoints": ["/users"],
  "expected_vulnerabilities": []
}
```

Expected vulnerabilities include endpoint path, method, attack category, expected severity,
affected parameter metadata, and description fields.

## Matching Behavior

The evaluator matches report findings against expected vulnerabilities using endpoint,
method, category, and related metadata where available. It produces:

- true positives;
- false positives;
- false negatives;
- unmatched findings;
- unmatched ground-truth entries.

## Metrics

Evaluation metrics include:

- total expected vulnerabilities;
- total findings;
- true positives;
- false positives;
- false negatives;
- precision;
- recall;
- F1 score;
- endpoint coverage;
- payload validity rate;
- total requests;
- total generated and executed payloads;
- findings by severity and category.

## Exports

The exporter writes JSON and CSV artifacts for findings, endpoints, matches, and metrics.
These exports can be used externally for thesis analysis or comparison workflows.

## Limitations

- Evaluation consumes an existing YSLFuzz report; it does not run scans by itself.
- Matching is deterministic but conservative.
- Third-party baseline comparison is not a core YSLFuzz feature.
