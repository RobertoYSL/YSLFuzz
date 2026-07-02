from pathlib import Path

from yslfuzz.config import ScanConfigLoader


def test_example_config_files_are_valid() -> None:
    for path in sorted(Path("examples/configs").glob("*.json")):
        config = ScanConfigLoader().load(path)
        assert config.target.base_url
        assert config.execution.dry_run is True
