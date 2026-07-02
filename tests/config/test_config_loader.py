import json
from pathlib import Path

import pytest

from yslfuzz.config import ConfigLoadError, ScanConfigLoader


def test_config_loader_loads_valid_json(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)

    config = ScanConfigLoader().load(config_path)

    assert config.target.base_url == "http://localhost:8000"
    assert Path(config.target.openapi_path).is_file()


def test_config_loader_loads_valid_yaml(tmp_path: Path) -> None:
    openapi_path = _copy_openapi(tmp_path)
    config_path = tmp_path / "scan.yaml"
    config_path.write_text(
        f"""
target:
  openapi_path: {openapi_path.name}
  base_url: http://localhost:8000
reporting:
  output: reports/out.json
""",
        encoding="utf-8",
    )

    config = ScanConfigLoader().load(config_path)

    assert Path(config.target.openapi_path) == openapi_path.resolve()


def test_config_loader_rejects_invalid_json_clearly(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid.json"
    config_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ConfigLoadError, match="Invalid scan config"):
        ScanConfigLoader().load(config_path)


def test_config_loader_resolves_relative_openapi_path_relative_to_config(
    tmp_path: Path,
) -> None:
    openapi_path = _copy_openapi(tmp_path)
    config_path = _write_config(tmp_path, openapi_path=openapi_path.name)

    config = ScanConfigLoader().load(config_path)

    assert Path(config.target.openapi_path) == openapi_path.resolve()


def test_config_loader_resolves_relative_output_path_relative_to_config(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, output="reports/report.json")

    config = ScanConfigLoader().load(config_path)

    assert Path(config.reporting.output) == (tmp_path / "reports" / "report.json").resolve()


def test_config_loader_fails_clearly_on_missing_openapi_path(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, openapi_path="missing.yaml")

    with pytest.raises(ConfigLoadError, match="OpenAPI file does not exist"):
        ScanConfigLoader().load(config_path)


def _copy_openapi(tmp_path: Path) -> Path:
    source = Path("examples/openapi/simple_users_api.yaml")
    target = tmp_path / "openapi.yaml"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _write_config(
    tmp_path: Path,
    *,
    openapi_path: str | None = None,
    output: str = "report.json",
) -> Path:
    if openapi_path is None:
        openapi_path = _copy_openapi(tmp_path).name
    config_path = tmp_path / "scan.json"
    config_path.write_text(
        json.dumps(
            {
                "target": {
                    "openapi_path": openapi_path,
                    "base_url": "http://localhost:8000",
                },
                "reporting": {"output": output},
            }
        ),
        encoding="utf-8",
    )
    return config_path
