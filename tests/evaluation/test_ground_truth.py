import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from yslfuzz.evaluation import GroundTruthLoadError, GroundTruthLoader
from yslfuzz.models import AttackCategory, FindingSeverity, HttpMethod
from yslfuzz.models.evaluation import ExpectedVulnerability


def test_ground_truth_json_file_loads_correctly() -> None:
    lab = GroundTruthLoader().load("examples/evaluation/simple_users_ground_truth.json")

    assert lab.lab_id == "simple_users_mock_lab"
    assert lab.expected_vulnerabilities[0].endpoint_method == HttpMethod.GET
    assert lab.expected_vulnerabilities[0].attack_category == AttackCategory.SQL_INJECTION


def test_invalid_ground_truth_file_fails_with_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"lab_id": "missing_required_fields"}), encoding="utf-8")

    with pytest.raises(GroundTruthLoadError, match="Invalid ground-truth file"):
        GroundTruthLoader().load(path)


def test_expected_vulnerability_model_validates_required_fields() -> None:
    vulnerability = ExpectedVulnerability(
        ground_truth_id="gt_1",
        endpoint_path="/users",
        endpoint_method=HttpMethod.GET,
        attack_category=AttackCategory.SQL_INJECTION,
        vulnerability_type="status_code_anomaly",
        expected_severity=FindingSeverity.MEDIUM,
        description="Expected test vulnerability.",
    )

    assert vulnerability.ground_truth_id == "gt_1"


def test_expected_vulnerability_requires_stable_endpoint_path() -> None:
    with pytest.raises(ValidationError):
        ExpectedVulnerability(
            ground_truth_id="gt_1",
            endpoint_path="users",
            endpoint_method=HttpMethod.GET,
            attack_category=AttackCategory.SQL_INJECTION,
            vulnerability_type="status_code_anomaly",
            expected_severity=FindingSeverity.MEDIUM,
            description="Expected test vulnerability.",
        )
