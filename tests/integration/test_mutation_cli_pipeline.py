import importlib
import json
from pathlib import Path


CLI_MAIN = importlib.import_module("yslfuzz.cli.main")
EXAMPLE_SCHEMA = Path("examples/openapi/simple_users_api.yaml")


def test_mutation_cli_pipeline_generates_payloads_in_dry_run(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"

    exit_code = CLI_MAIN.main(
        [
            "scan",
            "--openapi",
            str(EXAMPLE_SCHEMA),
            "--base-url",
            "http://testserver.local",
            "--output",
            str(output_path),
            "--include-boundary-payloads",
            "--dry-run",
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["metrics"]["boundary_payloads_generated"] > 0
    assert report["metrics"]["boundary_payloads_executed"] == 0
    assert report["payload_generation_summary"]["mutation_execution_enabled"] is False
