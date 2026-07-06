from yslfuzz.analysis.graphql import GraphQLAnalysisEngine
from yslfuzz.models import HttpMethod, PayloadCandidate, PayloadKind, RequestRecord, ResponseRecord


def test_graphql_analysis_engine_runs_deterministically_and_ignores_non_graphql() -> None:
    baseline_request = _request("baseline")
    baseline_response = _response("baseline", '{"data":{"user":{"id":"1"}}}')
    attack_request = _request("attack")
    attack_response = _response("attack", '{"data":{"user":{"id":"1"}}}')
    attack_payload = _payload()

    engine = GraphQLAnalysisEngine()
    first = engine.analyze(
        [(attack_request, attack_response, attack_payload)],
        baselines=[(baseline_request, baseline_response)],
    )
    second = engine.analyze(
        [(attack_request, attack_response, attack_payload)],
        baselines=[(baseline_request, baseline_response)],
    )

    assert [result.detector_id for result in first] == [result.detector_id for result in second]
    assert first
    assert engine.analyze(
        [(attack_request, attack_response, _payload(graphql=False))],
        baselines=[(baseline_request, baseline_response)],
    ) == []


def test_graphql_analysis_engine_builds_findings_with_recommendations() -> None:
    engine = GraphQLAnalysisEngine()
    _, findings = engine.analyze_findings(
        [(_request("attack"), _response("attack", '{"data":{"user":{"id":"1"}}}'), _payload())],
        scan_run_id="scan_1",
        baselines=[(_request("baseline"), _response("baseline", '{"data":{"user":{"id":"1"}}}'))],
    )

    assert findings
    assert findings[0].recommendation
    assert "GraphQL" in findings[0].title


def _request(prefix: str) -> RequestRecord:
    return RequestRecord(
        request_id=f"request_{prefix}",
        scan_run_id="scan_1",
        endpoint_id="endpoint_graphql_user",
        payload_id=f"payload_{prefix}",
        method=HttpMethod.POST,
        url="https://api.example.test/graphql",
        metadata={"api_style": "graphql", "graphql_operation_name": "YSLFuzzUser"},
    )


def _response(prefix: str, body_preview: str) -> ResponseRecord:
    return ResponseRecord(
        response_id=f"response_{prefix}",
        request_id=f"request_{prefix}",
        status_code=200,
        body_preview=body_preview,
        body_hash="hash",
        body_size_bytes=20,
    )


def _payload(*, graphql: bool = True) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_attack",
        endpoint_id="endpoint_graphql_user",
        payload_kind=PayloadKind.INVALID,
        content_type="application/json",
        body={
            "query": "query YSLFuzzUser($id: ID!) { user(id: $id) { id } }",
            "variables": {"id": 1},
            "operationName": "YSLFuzzUser",
        }
        if graphql
        else {"not_query": True},
        generation_strategy="graphql_test",
        seed=0,
        parent_payload_id="payload_valid",
        metadata={
            "api_style": "GRAPHQL" if graphql else "REST",
            "graphql_operation_name": "YSLFuzzUser",
            "graphql_operation_type": "query",
        }
        if graphql
        else {},
    )
