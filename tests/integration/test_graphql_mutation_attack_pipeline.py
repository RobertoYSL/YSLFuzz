import importlib
import json
from pathlib import Path


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")


def test_graphql_mutation_attack_dry_run_pipeline_generates_non_valid_payloads(tmp_path: Path) -> None:
    output_path = tmp_path / "graphql-mutation-attack.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--graphql-schema",
            "examples/graphql/simple_users_schema.graphql",
            "--base-url",
            "http://localhost:8080",
            "--include-boundary-payloads",
            "--include-invalid-payloads",
            "--include-mutated-payloads",
            "--include-attack-payloads",
            "--dry-run",
            "--output",
            str(output_path),
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["metrics"]["boundary_payloads_generated"] > 0
    assert report["metrics"]["invalid_payloads_generated"] > 0
    assert report["metrics"]["mutated_payloads_generated"] > 0
    assert report["metrics"]["attack_payloads_generated"] > 0
    assert report["graphql_execution_summary"]["graphql_requests_executed"] == 0
