from yslfuzz.execution import AttackExecutionConfig, AttackExecutionPlanner
from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    HttpMethod,
    PayloadCandidate,
    PayloadKind,
)
from yslfuzz.models.schema import Endpoint


def test_attack_execution_config_defaults_to_disabled() -> None:
    config = AttackExecutionConfig()

    assert config.enabled is False
    assert config.allow_sensitive_fields is False
    assert config.execute_only_safe_probes is True


def test_planner_returns_no_executable_attacks_when_disabled() -> None:
    plan = AttackExecutionPlanner().plan(_endpoint(), [_valid_payload()], [_attack_payload()])

    assert plan.payloads == []
    assert plan.blocked_reasons == ["attack execution disabled"]


def test_planner_filters_by_enabled_categories() -> None:
    attack = _attack_payload(category=AttackCategory.XSS)
    plan = AttackExecutionPlanner(
        AttackExecutionConfig(
            enabled=True,
            enabled_categories=[AttackCategory.SQL_INJECTION],
        )
    ).plan(_endpoint(), [_valid_payload()], [attack])

    assert plan.payloads == []
    assert "category disabled" in plan.blocked_reasons[0]


def test_planner_respects_max_attack_requests_per_endpoint() -> None:
    attacks = [_attack_payload(payload_id=f"payload_attack_{index}") for index in range(3)]
    plan = AttackExecutionPlanner(
        AttackExecutionConfig(enabled=True, max_attack_requests_per_endpoint=2)
    ).plan(_endpoint(), [_valid_payload()], attacks)

    assert len(plan.payloads) == 2


def test_planner_rejects_sensitive_targets_by_default() -> None:
    attack = _attack_payload(metadata={"non_executing": True, "target_sensitive": True})
    plan = AttackExecutionPlanner(AttackExecutionConfig(enabled=True)).plan(
        _endpoint(),
        [_valid_payload()],
        [attack],
    )

    assert plan.payloads == []
    assert "sensitive target blocked" in plan.blocked_reasons[0]


def test_planner_allows_sensitive_targets_only_when_explicitly_enabled() -> None:
    attack = _attack_payload(metadata={"non_executing": True, "target_sensitive": True})
    plan = AttackExecutionPlanner(
        AttackExecutionConfig(enabled=True, allow_sensitive_fields=True)
    ).plan(_endpoint(), [_valid_payload()], [attack])

    assert plan.payloads == [attack]


def _endpoint() -> Endpoint:
    return Endpoint(
        endpoint_id="endpoint_1",
        api_schema_id="api_schema_1",
        name="getUsers",
        api_style=ApiStyle.REST,
        path="/users",
        method=HttpMethod.GET,
    )


def _valid_payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload_id="payload_valid_1",
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.VALID,
        content_type="application/json",
        body=None,
        generation_strategy="test",
        seed=1,
    )


def _attack_payload(
    payload_id: str = "payload_attack_1",
    category: AttackCategory = AttackCategory.SQL_INJECTION,
    metadata: dict[str, object] | None = None,
) -> PayloadCandidate:
    return PayloadCandidate(
        payload_id=payload_id,
        endpoint_id="endpoint_1",
        payload_kind=PayloadKind.ATTACK,
        attack_category=category,
        content_type="application/json",
        body={"name": "yslfuzz_sqli_probe"},
        generation_strategy="attack",
        seed=1,
        parent_payload_id="payload_valid_1",
        metadata=metadata or {"non_executing": True, "target_field": "name"},
    )
