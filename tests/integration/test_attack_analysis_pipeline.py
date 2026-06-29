import json
from pathlib import Path

import httpx

from yslfuzz.analysis import AnalysisEngine
from yslfuzz.discovery import OpenAPIParser
from yslfuzz.execution import (
    AttackExecutionConfig,
    AttackExecutionPlanner,
    AttackExecutor,
    HttpExecutor,
    RequestBuilder,
    ScopeValidator,
)
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


def test_attack_analysis_pipeline_with_mock_transport_writes_redacted_report(tmp_path: Path) -> None:
    report_data, encoded, calls = _run_attack_pipeline(tmp_path / "attack-report.json")

    assert calls
    assert report_data["findings"]
    assert report_data["metrics"]["findings_total"] > 0
    assert report_data["reproducibility"]["total_deduplicated_findings"] == len(report_data["findings"])
    assert all(finding["fingerprint_hash"] for finding in report_data["findings"])
    assert "raw-token-value" not in encoded
    assert "Authorization" not in encoded
    assert "api_key" not in encoded.lower()


def test_repeated_attack_analysis_pipeline_has_stable_finding_fingerprints(tmp_path: Path) -> None:
    first, _, _ = _run_attack_pipeline(tmp_path / "attack-report-1.json")
    second, _, _ = _run_attack_pipeline(tmp_path / "attack-report-2.json")

    assert [finding["fingerprint_hash"] for finding in first["findings"]] == [
        finding["fingerprint_hash"] for finding in second["findings"]
    ]


def _run_attack_pipeline(output_path: Path) -> tuple[dict[str, object], str, list[str]]:
    api_schema = OpenAPIParser().parse(Path("examples/openapi/simple_users_api.yaml"))
    endpoint = next(
        endpoint
        for endpoint in api_schema.endpoints
        if endpoint.method == HttpMethod.GET and endpoint.path == "/users"
    )
    target = Target(
        name="localhost",
        base_url="http://localhost:8000",
        api_style=ApiStyle.REST,
        protocol=Protocol.HTTP,
        scope=ScopeDefinition(allowed_hosts=["localhost"]),
    )
    scan = ScanRun(
        project_id="project_1",
        target_id=target.target_id,
        scan_config_id="scan_config_1",
        api_schema_id=api_schema.api_schema_id,
    )

    valid_payload = PayloadGenerator(seed=1).generate_for_endpoint(endpoint)
    attack_payloads = AttackPayloadGenerator(
        AttackGenerationConfig(max_payloads_per_endpoint=1)
    ).generate(endpoint, valid_payload)

    request_builder = RequestBuilder()
    baseline_request = request_builder.build(endpoint, valid_payload, target, scan_run_id=scan.scan_run_id)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(200, json={"items": []})
        return httpx.Response(500, text="Unhandled Exception yslfuzz_probe token=raw-token-value")

    http_executor = HttpExecutor(httpx.Client(transport=httpx.MockTransport(handler)))
    baseline_result = http_executor.execute(baseline_request, scan_run_id=scan.scan_run_id)
    assert baseline_result.status == ExecutionStatus.COMPLETED
    baseline_response = http_executor.response_records[baseline_result.response_id]

    plan = AttackExecutionPlanner(
        AttackExecutionConfig(enabled=True, max_attack_requests_per_endpoint=1)
    ).plan(endpoint, [valid_payload], attack_payloads)
    attack_bundle = AttackExecutor(
        request_builder,
        ScopeValidator(),
        http_executor,
    ).execute_plan(plan, endpoint, target, scan_run_id=scan.scan_run_id)

    attack_records = [
        (request, response, attack_payloads[0])
        for request in attack_bundle.request_records
        for response in attack_bundle.response_records
        if response.request_id == request.request_id
    ]
    _, findings = AnalysisEngine().analyze(
        baseline_request,
        baseline_response,
        attack_records,
        scan_run_id=scan.scan_run_id,
    )
    report = JsonReporter().build_report(
        scan,
        endpoints=api_schema.endpoints,
        payloads=[valid_payload, *attack_payloads],
        requests=[baseline_request, *attack_bundle.request_records],
        responses=[baseline_response, *attack_bundle.response_records],
        execution_results=[baseline_result, *attack_bundle.execution_results],
        findings=findings,
        target=target,
    )
    output = JsonReporter().write_json(report, output_path)
    encoded = output.read_text(encoding="utf-8")
    report_data = json.loads(encoded)
    return report_data, encoded, calls
