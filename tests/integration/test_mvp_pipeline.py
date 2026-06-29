import json
from pathlib import Path
from typing import Any

import httpx

from yslfuzz.discovery import OpenAPIParser
from yslfuzz.execution import HttpExecutor, RequestBuilder, ScopeValidator
from yslfuzz.models import (
    ApiStyle,
    ExecutionStatus,
    HttpMethod,
    PayloadKind,
    Protocol,
    ScanRun,
    ScopeDefinition,
    SessionState,
    Target,
)
from yslfuzz.payloads import PayloadGenerator
from yslfuzz.reporting import JsonReporter, MetricsCalculator


EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


def test_openapi_to_json_report_mvp_pipeline(tmp_path: Path) -> None:
    api_schema = OpenAPIParser().parse(EXAMPLE_SCHEMA)
    endpoint = next(endpoint for endpoint in api_schema.endpoints if endpoint.name == "listUsers")
    payload = PayloadGenerator(seed=123).generate_for_endpoint(endpoint)
    target = Target(
        name="Simple Users API",
        base_url=api_schema.base_url,
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
    session_state = SessionState(
        headers={"Authorization": "Bearer raw-authorization-token"},
        cookies={"session_token": "raw-cookie-token"},
    )

    request_record = RequestBuilder().build(
        endpoint,
        payload,
        target,
        session_state=session_state,
        scan_run_id=scan.scan_run_id,
    )
    ScopeValidator().validate(request_record, target.scope)

    executor = HttpExecutor(client=httpx.Client(transport=httpx.MockTransport(_mock_users_api)))
    execution_result = executor.execute(request_record, scan_run_id=scan.scan_run_id)

    assert api_schema.title == "Simple Users API"
    assert endpoint.method == HttpMethod.GET
    assert payload.payload_kind == PayloadKind.VALID
    assert request_record.url == "http://localhost:8000/users"
    assert execution_result.status == ExecutionStatus.COMPLETED
    assert execution_result.response_id is not None

    response_record = executor.response_records[execution_result.response_id]
    assert response_record.status_code == 200
    assert response_record.response_id.startswith("response_")

    metrics = MetricsCalculator().calculate(
        scan_run_id=scan.scan_run_id,
        endpoints=api_schema.endpoints,
        payloads=[payload],
        requests=[request_record],
        responses=[response_record],
        execution_results=[execution_result],
    )
    assert metrics.total_endpoints == len(api_schema.endpoints)
    assert metrics.tested_endpoints == 1
    assert metrics.total_requests == 1
    assert metrics.successful_requests == 1
    assert metrics.payload_validity_rate == 1.0

    reporter = JsonReporter()
    report = reporter.build_report(
        scan,
        endpoints=api_schema.endpoints,
        payloads=[payload],
        requests=[request_record],
        responses=[response_record],
        execution_results=[execution_result],
        target=target,
        metrics=metrics,
    )
    output_path = reporter.write_json(report, tmp_path / "yslfuzz-report.json")
    decoded = json.loads(output_path.read_text(encoding="utf-8"))
    encoded = json.dumps(decoded)

    assert decoded["scan_run_id"] == scan.scan_run_id
    assert decoded["metrics"]["total_requests"] == 1
    assert decoded["metrics"]["successful_requests"] == 1
    assert decoded["request_response_summary"][0]["request"]["url"] == request_record.url
    assert decoded["request_response_summary"][0]["response"]["status_code"] == 200
    assert decoded["target_summary"]["name"] == "Simple Users API"
    assert "raw-authorization-token" not in encoded
    assert "raw-cookie-token" not in encoded
    assert "raw-response-secret" not in encoded
    assert "raw-body-token" not in encoded
    assert "raw-password" not in encoded
    assert "raw-api-key" not in encoded
    assert "raw-secret" not in encoded


def _mock_users_api(request: httpx.Request) -> httpx.Response:
    assert request.method == "GET"
    assert request.url.host == "localhost"
    assert request.url.path == "/users"
    assert "limit" in request.url.params

    response_body: dict[str, Any] = {
        "users": [
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "email": "user@example.test",
                "name": "Alice",
                "token": "raw-body-token",
                "password": "raw-password",
                "api_key": "raw-api-key",
                "secret": "raw-secret",
            }
        ]
    }
    return httpx.Response(
        200,
        headers={"Set-Cookie": "session=raw-response-secret"},
        json=response_body,
    )
