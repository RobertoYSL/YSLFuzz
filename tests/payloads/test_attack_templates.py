from yslfuzz.models import AttackCategory
from yslfuzz.payloads.attack_templates import default_attack_templates


def test_default_attack_templates_cover_mvp_categories() -> None:
    categories = {template.attack_category for template in default_attack_templates()}

    assert {
        AttackCategory.SQL_INJECTION,
        AttackCategory.NOSQL_INJECTION,
        AttackCategory.COMMAND_INJECTION,
        AttackCategory.SSRF,
        AttackCategory.XSS,
        AttackCategory.MASS_ASSIGNMENT,
        AttackCategory.BROKEN_ACCESS_CONTROL,
        AttackCategory.INPUT_VALIDATION,
        AttackCategory.INFORMATION_DISCLOSURE,
    }.issubset(categories)


def test_templates_use_safe_markers_only() -> None:
    encoded = repr([template.probe_value for template in default_attack_templates()]).lower()

    assert "yslfuzz" in encoded
    assert "169.254.169.254" not in encoded
    assert "metadata.google" not in encoded
    assert "<script" not in encoded
    assert "drop table" not in encoded
    assert "rm -rf" not in encoded
