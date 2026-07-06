"""Documentation presence checks for the user manual."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


REQUIRED_DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "index.md",
    ROOT / "docs" / "installation.md",
    ROOT / "docs" / "quickstart.md",
    ROOT / "docs" / "cli.md",
    ROOT / "docs" / "configuration.md",
    ROOT / "docs" / "authentication.md",
    ROOT / "docs" / "rest_openapi.md",
    ROOT / "docs" / "graphql.md",
    ROOT / "docs" / "payloads.md",
    ROOT / "docs" / "execution_safety.md",
    ROOT / "docs" / "reporting.md",
    ROOT / "docs" / "evaluation.md",
    ROOT / "docs" / "benchmarking.md",
    ROOT / "docs" / "labs.md",
    ROOT / "docs" / "performance.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "development.md",
    ROOT / "docs" / "limitations.md",
    ROOT / "docs" / "roadmap.md",
]


def test_required_documentation_files_exist() -> None:
    """The Milestone 27 manual pages should exist and be non-empty."""
    missing = [path for path in REQUIRED_DOCS if not path.is_file()]
    assert missing == []

    empty = [path for path in REQUIRED_DOCS if not path.read_text(encoding="utf-8").strip()]
    assert empty == []


def test_readme_links_to_documentation_index() -> None:
    """README should point new users to the documentation index."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/index.md" in readme
