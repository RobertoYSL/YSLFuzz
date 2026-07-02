from yslfuzz.benchmark import BenchmarkConfigLoader
from yslfuzz.evaluation import GroundTruthLoader
from yslfuzz.labs import LabCatalog, LabManifestLoader, LabPackValidator


def test_simple_users_lab_manifest_json_is_valid() -> None:
    manifest = LabManifestLoader().load("examples/labs/simple-users/lab_manifest.json")

    assert manifest.lab_id == "simple-users"


def test_simple_users_ground_truth_json_is_valid() -> None:
    ground_truth = GroundTruthLoader().load("examples/labs/simple-users/ground_truth.json")

    assert ground_truth.lab_id == "simple-users"
    assert len(ground_truth.expected_vulnerabilities) == 1


def test_simple_users_benchmark_json_is_valid() -> None:
    benchmark = BenchmarkConfigLoader().load("examples/labs/simple-users/benchmark.json")

    assert benchmark.benchmark_id == "simple_users_lab_benchmark"
    assert benchmark.jobs[0].dry_run is True
    assert benchmark.jobs[0].execute_attacks is False
    assert benchmark.jobs[0].execute_mutations is False


def test_catalog_and_validator_accept_example_labs() -> None:
    manifests = LabCatalog.discover("examples/labs")

    assert [manifest.lab_id for manifest in manifests] == ["simple-users"]
    for manifest in manifests:
        assert LabPackValidator().validate(manifest) == []
