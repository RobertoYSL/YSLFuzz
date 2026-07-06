from yslfuzz.models import ScanRun
from yslfuzz.reporting import JsonReporter


def test_report_includes_graphql_mutation_attack_summary() -> None:
    summary = {
        "graphql_boundary_payloads_generated": 1,
        "graphql_invalid_payloads_generated": 1,
        "graphql_mutated_payloads_generated": 1,
        "graphql_attack_payloads_generated": 1,
        "graphql_payloads_skipped_not_authorized": 2,
        "graphql_payloads_skipped_dry_run": 0,
        "graphql_attack_categories_generated": ["XSS"],
        "graphql_mutation_operator_counts": {"attack_reflection_marker": 1},
        "graphql_inert_markers_used": ["yslfuzz_graphql_reflection_marker"],
        "graphql_introspection_probe_generated": False,
        "mutation_execution_enabled": False,
        "attack_execution_enabled": False,
        "dry_run": False,
    }

    report = JsonReporter().build_report(
        ScanRun(
            scan_run_id="scan_1",
            project_id="project_1",
            target_id="target_1",
            scan_config_id="scan_config_1",
            api_schema_id="api_schema_1",
        ),
        metadata={"graphql_mutation_attack_generation": summary},
    )
    decoded = JsonReporter().to_dict(report)

    assert decoded["graphql_mutation_attack_summary"] == summary
    assert decoded["payload_generation_summary"]["graphql_mutation_attack_generation"] == summary
