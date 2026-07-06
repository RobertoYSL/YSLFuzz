import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from yslfuzz.config import ScanConfig, ScanConfigLoader
from yslfuzz.models import ApiStyle


def test_config_graphql_fields_work_if_implemented() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "api_style": "GRAPHQL",
                "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
                "base_url": "http://localhost:8080",
            }
        }
    )

    assert config.target.api_style == ApiStyle.GRAPHQL
    assert config.target.graphql_schema_path == "examples/graphql/simple_users_schema.graphql"
    assert config.target.openapi_path is None
    assert config.payloads.graphql_max_selection_depth == 2
    assert config.payloads.graphql_max_fields_per_selection == 5


def test_config_graphql_payload_fields_work_if_implemented() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "api_style": "GRAPHQL",
                "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
                "base_url": "http://localhost:8080",
            },
            "payloads": {
                "graphql_include_queries": False,
                "graphql_include_mutations": True,
                "graphql_max_selection_depth": 1,
                "graphql_max_fields_per_selection": 2,
                "graphql_max_operations": 1,
            },
        }
    )

    assert config.payloads.graphql_include_queries is False
    assert config.payloads.graphql_include_mutations is True
    assert config.payloads.graphql_max_selection_depth == 1
    assert config.payloads.graphql_max_fields_per_selection == 2
    assert config.payloads.graphql_max_operations == 1


def test_config_graphql_execution_fields_work_if_implemented() -> None:
    config = ScanConfig.model_validate(
        {
            "target": {
                "api_style": "GRAPHQL",
                "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
                "base_url": "http://localhost:8080",
            },
            "graphql": {
                "endpoint_path": "/api/graphql",
                "max_selection_depth": 1,
                "max_fields_per_selection": 2,
                "include_queries": True,
                "include_mutations": False,
                "max_requests": 20,
            },
            "execution": {"dry_run": True, "timeout": 5, "max_requests": 50},
        }
    )

    assert config.graphql.endpoint_path == "/api/graphql"
    assert config.graphql.max_selection_depth == 1
    assert config.graphql.max_fields_per_selection == 2
    assert config.graphql.include_queries is True
    assert config.graphql.include_mutations is False
    assert config.graphql.max_requests == 20
    assert config.execution.dry_run is True


def test_config_graphql_rejects_mixed_openapi_and_graphql_inputs() -> None:
    with pytest.raises(ValidationError, match="must not set openapi_path"):
        ScanConfig.model_validate(
            {
                "target": {
                    "api_style": "GRAPHQL",
                    "openapi_path": "examples/openapi/simple_users_api.yaml",
                    "graphql_schema_path": "examples/graphql/simple_users_schema.graphql",
                    "base_url": "http://localhost:8080",
                }
            }
        )


def test_config_loader_resolves_relative_graphql_schema_path(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.graphql"
    schema_path.write_text(
        Path("examples/graphql/simple_users_schema.graphql").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config_path = tmp_path / "scan.json"
    config_path.write_text(
        json.dumps(
            {
                "target": {
                    "api_style": "GRAPHQL",
                    "graphql_schema_path": "schema.graphql",
                    "base_url": "http://localhost:8080",
                },
                "reporting": {"output": "report.json"},
            }
        ),
        encoding="utf-8",
    )

    config = ScanConfigLoader().load(config_path)

    assert Path(config.target.graphql_schema_path or "") == schema_path.resolve()
