import json
from pathlib import Path

import httpx

from yslfuzz.analysis import AnalysisEngine
from yslfuzz.discovery import OpenAPIParser
from yslfuzz.execution import HttpExecutor, RequestBuilder
from yslfuzz.models import (
    ApiStyle,
    ExecutionStatus,
    HttpMethod,
    Protocol,
    ScanRun,
    ScopeDefinition,
    Target,
)
from yslfuzz.payloads import AttackGenerationConfig, AttackPayloadGenerator, PayloadGenerator
from yslfuzz.reporting import JsonReporter


def test_enriched_report_pipeline_with_mock_transport(tmp_path: Path) -> None:
    api_schema = OpenAPIParser().parse(Path("examples/openapi/simple_users_api.yaml"))
    endpoint = next(
        endpoint
        for endpoint in api_schema.endpoints
        if endpoint.method == HttpMethod.GET and endpoint.path == "/users"
    )
    target = Target(
        target_id="target_1",
        name="localhost",
        base_url="http://localhost:8000",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )
    scan = ScanRun(
        scan_run_id="scan_1",
        project_id="project_1",
        target_id=target.target_id,
        scan_config_id="scan_config_1",
        api_schema_id=api_schema.api_schema_id,
    )
    valid_payload = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)
    attack_payload = AttackPayloadGenerator(
        AttackGenerationConfig(max_payloads_per_endpoint=1)
    ).generate(endpoint, valid_payload)[0]
    request_builder = RequestBuilder()
    baseline_request = request_builder.build(endpoint, valid_payload, target, scan_run_id=scan.scan_run_id)
    attack_request = request_builder.build(endpoint, attack_payload, target, scan_run_id=scan.scan_run_id)

    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json={"items": []})
        return httpx.Response(500, text="Unhandled Exception yslfuzz_probe token=raw-token-value")

    executor = HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler)))
    baseline_result = executor.execute(baseline_request, scan.scan_run_id)
    attack_result = executor.execute(attack_request, scan.scan_run_id)
    assert baseline_result.status == ExecutionStatus.COMPLETED
    assert attack_result.status == ExecutionStatus.COMPLETED
    baseline_response = executor.response_records[baseline_result.response_id]
    attack_response = executor.response_records[attack_result.response_id]
    _, findings = AnalysisEngine().analyze(
        baseline_request,
        baseline_response,
        [(attack_request, attack_response, attack_payload)],
        scan.scan_run_id,
    )

    report = JsonReporter().build_report(
        scan,
        api_schema=api_schema,
        payloads=[valid_payload, attack_payload],
        requests=[baseline_request, attack_request],
        responses=[baseline_response, attack_response],
        execution_results=[baseline_result, attack_result],
        findings=findings,
        target=target,
    )
    output = JsonReporter().write_json(report, tmp_path / "report.json")
    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["report_schema_version"] == "1.0"
    assert data["findings"]
    assert data["findings"][0]["endpoint_path"] == "/users"
    assert data["endpoint_summary"]
    assert data["payload_summary"]["generated_by_kind"]["ATTACK"] == 1
    assert "raw-token-value" not in output.read_text(encoding="utf-8")
