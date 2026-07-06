from yslfuzz.models import (
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    SecurityFinding,
    ScanRun,
)
from yslfuzz.reporting import JsonReporter


def test_report_includes_graphql_analysis_summary_without_secret_values() -> None:
    finding = SecurityFinding(
        scan_run_id="scan_1",
        endpoint_id="endpoint_graphql_user",
        title="Possible GraphQL Error Disclosure",
        description="GraphQL errors contain internal-looking details.",
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.LOW,
        payload_id="payload_1",
        request_ids=["request_1"],
        response_ids=["response_1"],
        evidence=[
            Evidence(
                evidence_type="GRAPHQL_ERROR_DISCLOSURE",
                source="GraphQLErrorDisclosureDetector",
                description="redacted",
                observed_value_preview="secret-token-value",
                redacted=True,
            )
        ],
        metadata={
            "detector_id": "detector_graphql_error_disclosure",
            "detector_name": "GraphQLErrorDisclosureDetector",
            "api_style": "graphql",
        },
    )
    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        findings=[finding],
    )

    decoded = JsonReporter().to_dict(report)

    assert decoded["graphql_analysis_summary"]["graphql_findings_total"] == 1
    assert decoded["graphql_analysis_summary"]["graphql_error_disclosure_findings"] == 1
    assert "secret-token-value" not in JsonReporter().to_json(report)

