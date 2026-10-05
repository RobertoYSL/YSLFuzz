# Reporting

The primary scan report format is redacted JSON.

## Report Generation

`yslfuzz scan --output PATH` writes a JSON report. The report includes a
`report_schema_version` field, scan metadata, metrics, summaries, generated payload counts,
response records, analysis findings, and reproducibility metadata.

## Findings and Evidence

Analysis results are conservative. Findings include severity, confidence, category, endpoint
context when available, and bounded evidence. GraphQL detectors report possible signals such
as error disclosure, marker reflection, validation bypass, introspection exposure, mass
assignment behavior, injection marker behavior, and SSRF marker handling.

Findings should be reviewed manually. YSLFuzz avoids claiming confirmed vulnerabilities when
the evidence is signal-based.

## Summaries

Reports may include:

- endpoint summaries;
- payload summaries;
- attack category summaries;
- GraphQL payload and execution summaries;
- GraphQL detector summaries;
- stability summaries such as skipped request counts and retry counts.

## Executive Markdown Reports

YSLFuzz can generate an executive Markdown report alongside the JSON report using `--markdown PATH`:

```bash
uv run yslfuzz scan \
  --openapi examples/openapi/simple_users_api.yaml \
  --base-url http://localhost:8000 \
  --preset deep \
  -y \
  --output reports/scan_report.json \
  --markdown reports/scan_report.md
```

The Markdown report provides an executive overview formatted for review:
- Target and scan metadata (scan run ID, target URL, API style).
- Severity breakdown table (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- Endpoint summary table with request counts, finding counts, and highest severity per endpoint.
- Grouped finding sections with confidence levels, attack categories, triggering detectors, and syntax-highlighted evidence previews.

## Terminal Summary

At the end of every scan execution, YSLFuzz prints a concise summary banner to the console:
- Target base URL and execution mode.
- Tested endpoints, executed requests, and payload distribution.
- Workflow execution results and propagated dynamic parameters.
- Finding totals by severity.
- Top vulnerable endpoints highlighted with their respective severities.

## Redaction

Reports redact authentication headers, cookies, sensitive payload values, and environment-
derived material. Do not store real secrets in config files or example reports.

## Limitations

Interactive HTML reports and visual dashboard rendering are not current core features.
The primary outputs remain reproducible, machine-readable JSON and human-readable Markdown.
