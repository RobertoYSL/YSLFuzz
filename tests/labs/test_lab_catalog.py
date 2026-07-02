import json
from pathlib import Path

from yslfuzz.labs import LabCatalog


def test_lab_catalog_discovers_simple_users_lab() -> None:
    manifests = LabCatalog.discover("examples/labs")

    assert "simple-users" in {manifest.lab_id for manifest in manifests}


def test_lab_catalog_output_ordering_is_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "labs"
    _write_lab(root, "z-lab")
    _write_lab(root, "a-lab")

    manifests = LabCatalog.discover(root)

    assert [manifest.lab_id for manifest in manifests] == ["a-lab", "z-lab"]


def test_lab_catalog_exposes_lab_id_and_lab_name() -> None:
    manifest = LabCatalog.discover("examples/labs")[0]
    summary = manifest.catalog_summary()

    assert summary["lab_id"] == manifest.lab_id
    assert summary["lab_name"] == manifest.lab_name


def _write_lab(root: Path, lab_id: str) -> None:
    lab_dir = root / lab_id
    lab_dir.mkdir(parents=True)
    (lab_dir / "openapi.yaml").write_text(_openapi(), encoding="utf-8")
    (lab_dir / "ground_truth.json").write_text(json.dumps(_ground_truth(lab_id)), encoding="utf-8")
    (lab_dir / "benchmark.json").write_text(json.dumps(_benchmark()), encoding="utf-8")
    (lab_dir / "lab_manifest.json").write_text(json.dumps(_manifest(lab_id)), encoding="utf-8")


def _manifest(lab_id: str) -> dict[str, object]:
    return {
        "lab_id": lab_id,
        "lab_name": lab_id,
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
        "expected_vulnerability_count": 0,
        "expected_endpoint_count": 1,
    }


def _ground_truth(lab_id: str) -> dict[str, object]:
    return {
        "lab_id": lab_id,
        "lab_name": lab_id,
        "lab_version": "0.1.0",
        "target_name": "target",
        "target_base_url": "http://localhost:8000",
        "api_style": "REST",
        "expected_vulnerabilities": [],
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
