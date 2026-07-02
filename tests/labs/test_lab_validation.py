import json
from pathlib import Path

from yslfuzz.labs import LabManifestLoader, LabPackValidator


def test_lab_validation_detects_duplicate_ground_truth_id_values(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    data = _ground_truth()
    vulnerabilities = data["expected_vulnerabilities"]
    assert isinstance(vulnerabilities, list)
    vulnerabilities.append(dict(vulnerabilities[0]))
    (lab_dir / "ground_truth.json").write_text(json.dumps(data), encoding="utf-8")
    manifest = LabManifestLoader().load(lab_dir)

    issues = LabPackValidator().validate(manifest)

    assert "duplicate_ground_truth_id" in {issue.code for issue in issues}


def test_lab_validation_detects_unknown_endpoint_references(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    data = _ground_truth()
    vulnerability = data["expected_vulnerabilities"][0]
    assert isinstance(vulnerability, dict)
    vulnerability["endpoint_path"] = "/missing"
    (lab_dir / "ground_truth.json").write_text(json.dumps(data), encoding="utf-8")
    manifest = LabManifestLoader().load(lab_dir)

    issues = LabPackValidator().validate(manifest)

    assert "unknown_endpoint_reference" in {issue.code for issue in issues}


def test_lab_validation_detects_unnormalized_endpoint_methods(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    data = _ground_truth()
    vulnerability = data["expected_vulnerabilities"][0]
    assert isinstance(vulnerability, dict)
    vulnerability["endpoint_method"] = "get"
    (lab_dir / "ground_truth.json").write_text(json.dumps(data), encoding="utf-8")
    manifest = LabManifestLoader().load(lab_dir)

    issues = LabPackValidator().validate(manifest)

    assert "unnormalized_endpoint_method" in {issue.code for issue in issues}


def test_lab_validation_detects_invalid_attack_category(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    data = _ground_truth()
    vulnerability = data["expected_vulnerabilities"][0]
    assert isinstance(vulnerability, dict)
    vulnerability["attack_category"] = "UNSUPPORTED"
    (lab_dir / "ground_truth.json").write_text(json.dumps(data), encoding="utf-8")
    manifest = LabManifestLoader().load(lab_dir)

    issues = LabPackValidator().validate(manifest)

    assert "invalid_attack_category" in {issue.code for issue in issues}


def test_lab_validation_accepts_valid_simple_users_lab_pack() -> None:
    manifest = LabManifestLoader().load("examples/labs/simple-users/lab_manifest.json")

    issues = LabPackValidator().validate(manifest)

    assert issues == []


def _write_lab(root: Path) -> Path:
    lab_dir = root / "lab"
    lab_dir.mkdir(parents=True)
    (lab_dir / "openapi.yaml").write_text(_openapi(), encoding="utf-8")
    (lab_dir / "ground_truth.json").write_text(json.dumps(_ground_truth()), encoding="utf-8")
    (lab_dir / "benchmark.json").write_text(json.dumps(_benchmark()), encoding="utf-8")
    (lab_dir / "lab_manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    return lab_dir


def _manifest() -> dict[str, object]:
    return {
        "lab_id": "lab",
        "lab_name": "Lab",
        "lab_version": "0.1.0",
        "description": "Temporary lab.",
        "target_name": "target",
        "target_type": "MOCK",
        "api_style": "REST",
        "openapi_path": "openapi.yaml",
        "ground_truth_path": "ground_truth.json",
        "benchmark_config_path": "benchmark.json",
        "recommended_base_url": "http://localhost:8000",
        "setup_type": "MANUAL",
        "expected_vulnerability_count": 1,
        "expected_endpoint_count": 1,
    }


def _ground_truth() -> dict[str, object]:
    return {
        "lab_id": "lab",
        "lab_name": "Lab",
        "lab_version": "0.1.0",
        "target_name": "target",
        "target_base_url": "http://localhost:8000",
        "api_style": "REST",
        "expected_vulnerabilities": [
            {
                "ground_truth_id": "gt_1",
                "endpoint_path": "/users",
                "endpoint_method": "GET",
                "attack_category": "SQL_INJECTION",
                "vulnerability_type": "mock_signal",
                "expected_severity": "MEDIUM",
                "description": "Mock signal.",
            }
        ],
        "expected_endpoints": ["/users"],
    }


def _benchmark() -> dict[str, object]:
    return {
        "benchmark_id": "benchmark",
        "benchmark_name": "Benchmark",
        "benchmark_version": "0.1.0",
        "jobs": [
            {
                "job_id": "job",
                "job_name": "Job",
                "target_name": "target",
                "base_url": "http://localhost:8000",
                "openapi_path": "openapi.yaml",
            }
        ],
    }


def _openapi() -> str:
    return """
openapi: 3.0.3
info:
  title: Temporary
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        "200":
          description: OK
"""
