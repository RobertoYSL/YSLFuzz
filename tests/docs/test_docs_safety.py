"""Safety checks for user-facing documentation examples."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _documentation_paths() -> list[Path]:
    docs = sorted((ROOT / "docs").glob("*.md"))
    examples = sorted((ROOT / "examples").glob("**/*.md"))
    return [ROOT / "README.md", *docs, *examples]


def test_docs_do_not_include_obvious_secret_values() -> None:
    """Docs should use environment variable names, not raw-looking secret values."""
    forbidden = [
        re.compile(r"Bearer\s+[A-Za-z0-9._-]{16,}", re.IGNORECASE),
        re.compile(r"\bsk-[A-Za-z0-9]{12,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{12,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
        re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\b"),
    ]
    for path in _documentation_paths():
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert pattern.search(text) is None, f"{path} contains a raw-looking secret value"


def test_docs_do_not_include_operational_exploit_examples() -> None:
    """Docs should avoid operational exploit strings and reserved cloud metadata targets."""
    forbidden_literals = [
        " or 1=1",
        "union select",
        "drop table",
        "$ne",
        "$where",
        "/bin/sh",
        "cat /etc/passwd",
        "169.254.169.254",
        "metadata.google",
        "latest/meta-data",
    ]
    for path in _documentation_paths():
        lowered = path.read_text(encoding="utf-8").lower()
        for literal in forbidden_literals:
            assert literal not in lowered, f"{path} contains prohibited example text: {literal}"


def test_docs_do_not_show_localhost_or_private_ssrf_payloads() -> None:
    """Localhost base URLs are fine; localhost/private SSRF examples are not."""
    private_target = re.compile(
        r"(ssrf|server-side request forgery).*(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)",
        re.IGNORECASE,
    )
    for path in _documentation_paths():
        for line in path.read_text(encoding="utf-8").splitlines():
            assert private_target.search(line) is None, f"{path} contains a local/private SSRF example"
