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
  "lab_id": "owasp-crapi",
  "lab_name": "OWASP crAPI Benchmark Lab",
  "lab_version": "1.0.0",
  "target_name": "crAPI",
  "target_base_url": "http://127.0.0.1:8888",
  "api_style": "REST",
  "expected_endpoints": ["/community/api/v2/community/posts", "..."],
  "expected_vulnerabilities": []
}
```

Predefined ground-truth datasets are provided in `examples/evaluation/`:
- `crapi_ground_truth.json`: Official OWASP crAPI benchmark mapping 13 challenges (BOLA, broken auth, excessive data exposure, mass assignment, SSRF, NoSQLi, SQLi).
- `simple_users_ground_truth.json`: Minimal mock lab ground truth for deterministic test suites.

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
