import json

from yslfuzz.analysis import AnalysisConfig
from yslfuzz.models import (
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    REDACTED_VALUE,
    ScanRun,
    SecurityFinding,
)
from yslfuzz.reporting import JsonReporter


def test_json_report_includes_analysis_summary() -> None:
    finding = _finding()
    report = JsonReporter().build_report(
        _scan(),
        findings=[finding],
        metadata={
            "total_detector_results": 1,
            "analysis_config": AnalysisConfig(
                disabled_detectors=["ReflectionDetector"]
            ).summary(),
            "analysis_detectors": [
                {
                    "detector_id": "detector_sensitive_data_exposure",
                    "name": "SensitiveDataExposureDetector",
                    "version": "0.1.0",
                }
            ],
        },
    )

    decoded = json.loads(JsonReporter().to_json(report))
    summary = decoded["analysis_summary"]

    assert summary["detector_result_count"] == 1
    assert summary["finding_count_by_detector"] == {"SensitiveDataExposureDetector": 1}
    assert summary["finding_count_by_severity"] == {"MEDIUM": 1}
    assert summary["analysis_configuration"]["disabled_detectors"] == ["ReflectionDetector"]
    assert summary["detectors"][0]["name"] == "SensitiveDataExposureDetector"


def test_json_report_analysis_evidence_remains_redacted() -> None:
    encoded = JsonReporter().to_json(JsonReporter().build_report(_scan(), findings=[_finding()]))

    assert "raw-token-value" not in encoded
    assert REDACTED_VALUE in encoded


def _scan() -> ScanRun:
    return ScanRun(
        scan_run_id="scan_1",
        project_id="project_1",
        target_id="target_1",
        scan_config_id="scan_config_1",
        api_schema_id="schema_1",
    )


def _finding() -> SecurityFinding:
    return SecurityFinding(
        finding_id="finding_1",
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="Possible Sensitive Data Exposure",
        description="sensitive data exposure indicator",
        attack_category=AttackCategory.INFORMATION_DISCLOSURE,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        request_ids=["request_1"],
        response_ids=["response_1"],
        evidence=[
            Evidence(
                evidence_type="sensitive_key_exposure",
                source="SensitiveDataExposureDetector",
                description="Sensitive-looking key appeared in response preview.",
                request_id="request_1",
                response_id="response_1",
                observed_value_preview="raw-token-value",
                redacted=True,
            )
        ],
        metadata={
            "detector_id": "detector_sensitive_data_exposure",
            "detector_name": "SensitiveDataExposureDetector",
            "detector_version": "0.1.0",
        },
    )
