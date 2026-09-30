from pathlib import Path

from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ScanRun,
    SecurityFinding,
)
from yslfuzz.models.reporting import Report
from yslfuzz.models.schema import Endpoint
from yslfuzz.reporting import JsonReporter, MarkdownReporter


def test_markdown_reporter_renders_severity_summary() -> None:
    markdown = MarkdownReporter().to_markdown(_report())

    assert "## Severity Summary" in markdown
    assert "| HIGH | 1 |" in markdown


def test_markdown_reporter_renders_findings() -> None:
    markdown = MarkdownReporter().to_markdown(_report())

    assert "### Status Code Anomaly" in markdown
    assert "Recommendation" in markdown


def test_markdown_reporter_remains_redacted() -> None:
    markdown = MarkdownReporter().to_markdown(_report(secret_preview="token=raw-token-value"))

    assert "raw-token-value" not in markdown
    assert "[REDACTED]" in markdown


def test_markdown_reporter_write_markdown(tmp_path: Path) -> None:
    reporter = MarkdownReporter()
    target_file = tmp_path / "subdir" / "report.md"
    written_path = reporter.write_markdown(_report(), target_file)

    assert written_path == target_file
    assert target_file.exists()
    assert "# YSLFuzz Scan Report" in target_file.read_text(encoding="utf-8")


def test_markdown_reporter_renders_stateful_workflows() -> None:
    rep = _report()
    rep.metadata["stateful_workflows"] = {
        "enabled": True,
        "workflows_detected": 5,
        "workflows_executed": 3,
        "known_values_extracted": 2,
    }
    markdown = MarkdownReporter().to_markdown(rep)

    assert "## Stateful Workflows" in markdown
    assert "Workflows detected: `5`" in markdown
    assert "Workflows executed: `3`" in markdown


def _report(secret_preview: str = "200->500") -> Report:
    endpoint = Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="schema_1",
        name="list_users",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )
    return JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="schema_1",
        ),
        endpoints=[endpoint],
        payloads=[
            PayloadCandidate(
                payload_id="payload_attack",
                endpoint_id="endpoint_1",
                payload_kind=PayloadKind.ATTACK,
                attack_category=AttackCategory.SQL_INJECTION,
                content_type="application/json",
                generation_strategy="attack",
                seed=1,
            )
        ],
        requests=[
            RequestRecord(
                request_id="request_1",
                scan_run_id="scan_1",
                endpoint_id="endpoint_1",
                payload_id="payload_attack",
                method=HttpMethod.GET,
                url="https://api.example.test/users",
            )
        ],
        findings=[_finding(secret_preview)],
    )


def _finding(secret_preview: str) -> SecurityFinding:
    return SecurityFinding(
        finding_id="finding_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Status Code Anomaly",
        description="status changed",
        attack_category=AttackCategory.SQL_INJECTION,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        payload_id="payload_attack",
        request_ids=["request_1"],
        evidence=[
            Evidence(
                evidence_type="status_code",
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id="request_1",
                observed_value_preview=secret_preview,
                redacted=True,
            )
        ],
        recommendation="Review status handling.",
        metadata={
            "detector_id": "detector_status_code_anomaly",
            "detector_name": "StatusCodeAnomalyDetector",
            "detector_version": "0.1.0",
        },
    )
