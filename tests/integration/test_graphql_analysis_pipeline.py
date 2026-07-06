from yslfuzz.analysis import AnalysisEngine
from yslfuzz.models import AttackCategory, HttpMethod, PayloadCandidate, PayloadKind, RequestRecord, ResponseRecord


def test_graphql_analysis_pipeline_creates_finding_from_executed_marker_response() -> None:
    baseline_request = RequestRecord(
        request_id="request_baseline",
        scan_run_id="scan_1",
        endpoint_id="endpoint_graphql_user",
        payload_id="payload_valid",
        method=HttpMethod.POST,
        url="https://api.example.test/graphql",
        metadata={"api_style": "graphql"},
    )
    baseline_response = ResponseRecord(
        response_id="response_baseline",
        request_id="request_baseline",
        status_code=200,
        body_preview='{"data":{"user":{"id":"1"}}}',
        body_hash="baseline",
        body_size_bytes=28,
    )
    attack_request = RequestRecord(
        request_id="request_attack",
        scan_run_id="scan_1",
        endpoint_id="endpoint_graphql_user",
        payload_id="payload_attack",
        method=HttpMethod.POST,
        url="https://api.example.test/graphql",
        metadata={"api_style": "graphql"},
    )
    attack_response = ResponseRecord(
        response_id="response_attack",
        request_id="request_attack",
        status_code=200,
        body_preview='{"data":{"echo":"yslfuzz_graphql_reflection_marker"}}',
        body_hash="attack",
        body_size_bytes=54,
    )
    payload = PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_graphql_user",
        payload_kind=PayloadKind.ATTACK,
        attack_category=AttackCategory.XSS,
        content_type="application/json",
        body={"query": "query Q { echo }", "variables": {}},
        generation_strategy="graphql_attack_probe_mvp",
        seed=0,
        metadata={
            "api_style": "GRAPHQL",
            "inert_marker": "yslfuzz_graphql_reflection_marker",
        },
    )

    _, findings = AnalysisEngine().analyze_records(
        [(baseline_request, baseline_response)],
        [(attack_request, attack_response, payload)],
        scan_run_id="scan_1",
    )

    assert findings
    assert any(finding.title == "Possible GraphQL Marker Reflection" for finding in findings)
