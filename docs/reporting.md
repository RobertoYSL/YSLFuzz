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

## Redaction

Reports redact authentication headers, cookies, sensitive payload values, and environment-
derived material. Do not store real secrets in config files or example reports.

## Markdown

A minimal Markdown renderer exists in the reporting package for library use. The scan CLI
currently documents JSON as the main report output format.

## Limitations

HTML report finalization and advanced Markdown report polishing are not documented as
completed product features.
