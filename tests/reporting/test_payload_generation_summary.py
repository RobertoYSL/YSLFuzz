from yslfuzz.models import (
    AttackCategory,
    PayloadCandidate,
    PayloadKind,
    RequestRecord,
    ScanRun,
    HttpMethod,
)
from yslfuzz.reporting import JsonReporter


def test_json_report_includes_payload_generation_summary() -> None:
    payloads = [
        _payload("payload_valid", PayloadKind.VALID),
        _payload("payload_boundary", PayloadKind.BOUNDARY),
        _payload("payload_invalid", PayloadKind.INVALID),
        _payload("payload_mutated", PayloadKind.MUTATED),
        _payload("payload_attack", PayloadKind.ATTACK, AttackCategory.XSS),
    ]
    requests = [
        RequestRecord(
            scan_run_id="scan_1",
            endpoint_id="endpoint_1",
            payload_id="payload_valid",
            method=HttpMethod.GET,
            url="https://api.example.test/users",
        ),
        RequestRecord(
            scan_run_id="scan_1",
            endpoint_id="endpoint_1",
            payload_id="payload_mutated",
            method=HttpMethod.GET,
            url="https://api.example.test/users",
        ),
    ]

    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        payloads=payloads,
        requests=requests,
        metadata={
            "mutation_config": {"include_sensitive_fields": False},
            "mutation_execution_enabled": True,
            "attack_execution_enabled": False,
            "random_seed": 0,
            "max_mutations_per_payload": 5,
            "max_mutations_per_field": 2,
        },
    )
    summary = JsonReporter().to_dict(report)["payload_generation_summary"]

    assert summary["generated_by_kind"]["BOUNDARY"] == 1
    assert summary["generated_by_kind"]["INVALID"] == 1
    assert summary["generated_by_kind"]["MUTATED"] == 1
    assert summary["executed_by_kind"]["VALID"] == 1
    assert summary["executed_by_kind"]["MUTATED"] == 1
    assert summary["skipped_by_kind"]["ATTACK"] == 1
    assert summary["mutation_config"] == {"include_sensitive_fields": False}
    assert summary["mutation_execution_enabled"] is True
    assert summary["attack_execution_enabled"] is False
    assert summary["max_mutations_per_payload"] == 5


def _payload(
    payload_id: str,
    kind: PayloadKind,
    attack_category: AttackCategory | None = None,
) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id=payload_id,
        endpoint_id="endpoint_1",
        payload_kind=kind,
        attack_category=attack_category,
        content_type="application/json",
        generation_strategy="test",
        seed=1,
    )
