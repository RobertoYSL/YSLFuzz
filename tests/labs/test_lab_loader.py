import json
from pathlib import Path

import pytest

from yslfuzz.labs import LabManifestLoadError, LabManifestLoader


def test_lab_manifest_loader_loads_valid_manifest(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)

    manifest = LabManifestLoader().load(lab_dir / "lab_manifest.json")

    assert manifest.lab_id == "tmp-lab"


def test_lab_manifest_loader_loads_from_lab_directory(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)

    manifest = LabManifestLoader().load(lab_dir)

    assert manifest.manifest_path is not None


def test_lab_manifest_loader_resolves_relative_openapi_path(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)

    manifest = LabManifestLoader().load(lab_dir)

    assert manifest.resolved_openapi_path == str((lab_dir / "openapi.yaml").resolve())


def test_lab_manifest_loader_resolves_relative_ground_truth_path(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)

    manifest = LabManifestLoader().load(lab_dir)

    assert manifest.resolved_ground_truth_path == str((lab_dir / "ground_truth.json").resolve())


def test_lab_manifest_loader_resolves_relative_benchmark_config_path(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)

    manifest = LabManifestLoader().load(lab_dir)

    assert manifest.resolved_benchmark_config_path == str((lab_dir / "benchmark.json").resolve())


def test_lab_manifest_loader_load_directory_returns_sorted_files(tmp_path: Path) -> None:
    root = tmp_path / "labs"
    _write_lab(root, lab_id="b-lab")
    _write_lab(root, lab_id="a-lab")

    manifests = LabManifestLoader().load_directory(root)

    assert [manifest.lab_id for manifest in manifests] == ["a-lab", "b-lab"]


def test_lab_manifest_loader_fails_clearly_on_missing_openapi_file(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    (lab_dir / "openapi.yaml").unlink()

    with pytest.raises(LabManifestLoadError, match="OpenAPI file does not exist"):
        LabManifestLoader().load(lab_dir)


def test_lab_manifest_loader_fails_clearly_on_missing_ground_truth_file(tmp_path: Path) -> None:
    lab_dir = _write_lab(tmp_path)
    (lab_dir / "ground_truth.json").unlink()

    with pytest.raises(LabManifestLoadError, match="ground truth file does not exist"):
        LabManifestLoader().load(lab_dir)


def _write_lab(root: Path, lab_id: str = "tmp-lab") -> Path:
    lab_dir = root / lab_id
    lab_dir.mkdir(parents=True, exist_ok=True)
    (lab_dir / "openapi.yaml").write_text(_openapi(), encoding="utf-8")
    (lab_dir / "ground_truth.json").write_text(json.dumps(_ground_truth(lab_id)), encoding="utf-8")
    (lab_dir / "benchmark.json").write_text(json.dumps(_benchmark()), encoding="utf-8")
    (lab_dir / "lab_manifest.json").write_text(json.dumps(_manifest(lab_id)), encoding="utf-8")
    return lab_dir


def _manifest(lab_id: str) -> dict[str, object]:
    return {
        "lab_id": lab_id,
        "lab_name": "Temporary Lab",
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


def _ground_truth(lab_id: str) -> dict[str, object]:
    return {
        "lab_id": lab_id,
        "lab_name": "Temporary Lab",
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
                "dry_run": True,
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
