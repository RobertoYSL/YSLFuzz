from pathlib import Path

from yslfuzz.config import ScanConfigLoader


def test_config_graphql_analysis_fields_work(tmp_path: Path) -> None:
    config_path = tmp_path / "graphql-config.yaml"
    schema_path = Path("examples/graphql/simple_users_schema.graphql").resolve()
    config_path.write_text(
        f"""
target:
  api_style: GRAPHQL
  graphql_schema_path: {schema_path}
  base_url: http://localhost:8080
graphql:
  enable_analysis: true
  include_introspection_probe: true
payloads:
  include_attack_payloads: true
  enabled_attack_categories:
    - SQL_INJECTION
    - SSRF
execution:
  dry_run: true
analysis:
  enable_graphql_error_disclosure: true
  enable_graphql_ssrf_marker_detection: true
reporting:
  output: report.json
""",
        encoding="utf-8",
    )

    config = ScanConfigLoader().load(config_path)

    assert config.graphql.enable_analysis is True
    assert config.graphql.include_introspection_probe is True
    assert config.analysis.enable_graphql_ssrf_marker_detection is True
