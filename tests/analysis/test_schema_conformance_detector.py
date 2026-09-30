"""Unit tests for SchemaConformanceDetector."""

from yslfuzz.analysis.detectors import SchemaConformanceDetector
from yslfuzz.models.enums import ApiStyle, FieldType, FindingSeverity, HttpMethod
from yslfuzz.models.execution import RequestRecord, ResponseRecord
from yslfuzz.models.schema import Endpoint, FieldDefinition, ResponseDefinition


def _build_test_endpoint() -> Endpoint:
    return Endpoint(
        endpoint_id="ep_test",
        api_schema_id="schema_1",
        name="GetItem",
        api_style=ApiStyle.REST,
        path="/items/{id}",
        method=HttpMethod.GET,
        responses=[
            ResponseDefinition(
                status_code=200,
                content_type="application/json",
                fields=[
                    FieldDefinition(name="id", field_type=FieldType.INTEGER, required=True),
                    FieldDefinition(name="title", field_type=FieldType.STRING, required=True),
                    FieldDefinition(name="active", field_type=FieldType.BOOLEAN, required=False),
                ],
            ),
            ResponseDefinition(status_code=404, content_type="application/json"),
        ],
    )


def test_schema_conformance_flags_undocumented_500() -> None:
    endpoint = _build_test_endpoint()
    detector = SchemaConformanceDetector(endpoints_by_id={endpoint.endpoint_id: endpoint})

    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/items/1",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=500,
        body_preview="Server crash",
    )

    results = detector.detect_baseline(req, resp)
    assert len(results) == 1
    assert results[0].severity == FindingSeverity.HIGH
    assert "500" in results[0].reason
    assert results[0].metadata["conformance_violation"] == "undocumented_status_code"


def test_schema_conformance_flags_content_type_mismatch() -> None:
    endpoint = _build_test_endpoint()
    detector = SchemaConformanceDetector(endpoints_by_id={endpoint.endpoint_id: endpoint})

    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/items/1",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_preview="<html>error page</html>",
    )

    results = detector.detect_baseline(req, resp)
    assert any(r.metadata.get("conformance_violation") == "content_type_mismatch" for r in results)


def test_schema_conformance_flags_missing_required_field() -> None:
    endpoint = _build_test_endpoint()
    detector = SchemaConformanceDetector(endpoints_by_id={endpoint.endpoint_id: endpoint})

    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/items/1",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_preview='{"id": 1}',  # missing 'title'
    )

    results = detector.detect_baseline(req, resp)
    missing = [r for r in results if r.metadata.get("conformance_violation") == "missing_required_field"]
    assert len(missing) == 1
    assert missing[0].metadata["target_field"] == "title"


def test_schema_conformance_flags_field_type_mismatch() -> None:
    endpoint = _build_test_endpoint()
    detector = SchemaConformanceDetector(endpoints_by_id={endpoint.endpoint_id: endpoint})

    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/items/1",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_preview='{"id": "not_an_int", "title": "Book"}',
    )

    results = detector.detect_baseline(req, resp)
    type_errs = [r for r in results if r.metadata.get("conformance_violation") == "field_type_mismatch"]
    assert len(type_errs) == 1
    assert type_errs[0].metadata["target_field"] == "id"


def test_schema_conformance_passes_conforming_response() -> None:
    endpoint = _build_test_endpoint()
    detector = SchemaConformanceDetector(endpoints_by_id={endpoint.endpoint_id: endpoint})

    req = RequestRecord(
        scan_run_id="scan_1",
        endpoint_id=endpoint.endpoint_id,
        method=HttpMethod.GET,
        url="http://localhost:8000/items/1",
    )
    resp = ResponseRecord(
        request_id=req.request_id,
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_preview='{"id": 1, "title": "Book", "active": true}',
    )

    results = detector.detect_baseline(req, resp)
    assert len(results) == 0
