import json

from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    Evidence,
    FindingConfidence,
    FindingSeverity,
    PayloadCandidate,
    PayloadKind,
    Protocol,
    ScanRun,
    ScopeDefinition,
    SecurityFinding,
    Target,
)
from yslfuzz.reporting import JsonReporter


def test_json_report_includes_fingerprint_hashes_and_evidence_counts() -> None:
    finding = _finding()
    report = JsonReporter().build_report(_scan(), payloads=[_payload()], findings=[finding])
    data = JsonReporter().to_dict(report)

    assert data["findings"][0]["fingerprint_hash"] == "stable-hash"
    assert data["findings"][0]["evidence_count"] == 1


def test_json_report_includes_reproducibility_metadata_and_counts() -> None:
    scan = _scan()
    report = JsonReporter().build_report(
        scan,
        payloads=[_payload()],
        findings=[_finding()],
        target=_target(),
        metadata={
            "attack_execution_enabled": True,
            "enabled_attack_categories": [AttackCategory.SQL_INJECTION.value],
            "total_detector_results": 3,
            "total_raw_findings": 3,
            "total_deduplicated_findings": 1,
        },
    )
    data = JsonReporter().to_dict(report)
    reproducibility = data["reproducibility"]

    assert reproducibility["yslfuzz_version"]
    assert reproducibility["scan_run_id"] == scan.scan_run_id
    assert reproducibility["api_schema_id"] == scan.api_schema_id
    assert reproducibility["target_id"] == "target_1"
    assert reproducibility["random_seed"] == 7
    assert reproducibility["attack_execution_enabled"] is True
    assert reproducibility["enabled_attack_categories"] == [AttackCategory.SQL_INJECTION.value]
    assert reproducibility["total_detector_results"] == 3
    assert reproducibility["total_raw_findings"] == 3
    assert reproducibility["total_deduplicated_findings"] == 1
    assert reproducibility["detectors"] == [{"name": "StatusCodeAnomalyDetector", "version": "0.1.0"}]


def test_json_report_reproducibility_metadata_remains_redacted() -> None:
    report = JsonReporter().build_report(
        _scan(),
        payloads=[_payload()],
        findings=[_finding(secret_preview="token=raw-token-value")],
        metadata={"raw_secret": "raw-token-value"},
    )
    encoded = json.dumps(JsonReporter().to_dict(report))

    assert "raw-token-value" not in encoded


def _scan() -> ScanRun:
    return ScanRun(
        scan_run_id="scan_1",
        project_id="project_1",
        target_id="target_1",
        scan_config_id="scan_config_1",
        api_schema_id="api_schema_1",
    )


def _target() -> Target:
    return Target(
        target_id="target_1",
        name="api.example.test",
        base_url="https://api.example.test",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTPS,
        scope=ScopeDefinition(allowed_hosts=["api.example.test"]),
    )


def _payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.SQL_INJECTION,
        content_type="application/json",
        generation_strategy="attack",
        seed=7,
        parent_payload_id="payload_valid",
    )


def _finding(secret_preview: str = "200->500") -> SecurityFinding:
    return SecurityFinding(
        scan_run_id="scan_1",
        endpoint_id="endpoint_1",
        title="StatusCodeAnomalyDetector signal for name",
        description="status changed",
        attack_category=AttackCategory.SQL_INJECTION,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        affected_parameter="name",
        payload_id="payload_attack",
        request_ids=["request_1"],
        response_ids=["response_1"],
        evidence=[
            Evidence(
                evidence_type="status_code",
                source="StatusCodeAnomalyDetector",
                description="status changed",
                request_id="request_1",
                response_id="response_1",
                observed_value_preview=secret_preview,
                redacted=False,
            )
        ],
        metadata={
            "detector_name": "StatusCodeAnomalyDetector",
            "fingerprint_hash": "stable-hash",
            "fingerprint": {"fingerprint_hash": "stable-hash"},
        },
    )
