from yslfuzz.evaluation import FindingMatcher
from yslfuzz.models import AttackCategory, FindingSeverity, HttpMethod
from yslfuzz.models.evaluation import ExpectedVulnerability, GroundTruthLab


def test_matcher_identifies_true_positive_by_endpoint_method_category() -> None:
    matches = FindingMatcher().match(_report([_finding("finding_1")]), _ground_truth())

    assert [match.match_status for match in matches] == ["true_positive"]
    assert matches[0].finding_id == "finding_1"
    assert matches[0].ground_truth_id == "gt_1"


def test_matcher_identifies_false_positive() -> None:
    matches = FindingMatcher().match(_report([_finding("finding_1", path="/orders")]), _ground_truth())

    assert {match.match_status for match in matches} == {"false_positive", "false_negative"}
    assert any(match.metadata.get("classification") == "unmatched_finding" for match in matches)


def test_matcher_identifies_false_negative() -> None:
    matches = FindingMatcher().match(_report([]), _ground_truth())

    assert [match.match_status for match in matches] == ["false_negative"]
    assert matches[0].metadata["classification"] == "unmatched_ground_truth"


def test_matcher_handles_multiple_findings_for_one_ground_truth_deterministically() -> None:
    matches = FindingMatcher().match(
        _report([_finding("finding_b"), _finding("finding_a")]),
        _ground_truth(),
    )

    true_positive = next(match for match in matches if match.match_status == "true_positive")
    false_positive = next(match for match in matches if match.match_status == "false_positive")
    assert true_positive.finding_id == "finding_a"
    assert false_positive.finding_id == "finding_b"


def test_matcher_does_not_use_timestamps_or_request_ids_for_matching() -> None:
    finding = _finding("finding_1")
    finding["request_ids"] = ["request_unrelated"]
    finding["created_at"] = "2099-01-01T00:00:00Z"

    matches = FindingMatcher().match(_report([finding]), _ground_truth())

    assert matches[0].match_status == "true_positive"


def _ground_truth() -> GroundTruthLab:
    return GroundTruthLab(
        lab_id="lab_1",
        lab_name="Lab",
        lab_version="0.1.0",
        target_name="target",
        target_base_url="https://api.example.test",
        api_style="REST",
        expected_vulnerabilities=[
            ExpectedVulnerability(
                ground_truth_id="gt_1",
                endpoint_path="/users",
                endpoint_method=HttpMethod.GET,
                attack_category=AttackCategory.SQL_INJECTION,
                vulnerability_type="status_code_anomaly",
                expected_severity=FindingSeverity.MEDIUM,
                affected_parameter="name",
                description="Expected vulnerability.",
            )
        ],
    )


def _report(findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "scan_run_id": "scan_1",
        "findings": findings,
    }


def _finding(finding_id: str, path: str = "/users") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "endpoint_path": path,
        "endpoint_method": "GET",
        "attack_category": "SQL_INJECTION",
        "severity": "MEDIUM",
        "affected_parameter": "name",
        "title": "Status Code Anomaly",
    }
