from yslfuzz.cli.main import _graphql_payloads_selected_for_execution
from yslfuzz.models.enums import AttackCategory, PayloadKind
from yslfuzz.models.payload import PayloadCandidate


def _payload(kind: PayloadKind) -> PayloadCandidate:
    return PayloadCandidate(
        endpoint_id=f"endpoint_{kind.value}",
        payload_kind=kind,
        content_type="application/json",
        body={"query": "query YSLFuzzHealth { health }", "variables": {}, "operationName": "YSLFuzzHealth"},
        generation_strategy="test",
        seed=0,
        attack_category=AttackCategory.INPUT_VALIDATION if kind == PayloadKind.ATTACK else None,
    )


def test_dry_run_selects_all_graphql_payloads_for_planning_only() -> None:
    selected = _graphql_payloads_selected_for_execution(
        valid_payloads=[_payload(PayloadKind.VALID)],
        mutation_payloads=[_payload(PayloadKind.MUTATED)],
        attack_payloads=[_payload(PayloadKind.ATTACK)],
        dry_run=True,
        execute_mutations=False,
        execute_attacks=False,
    )

    assert [payload.payload_kind for payload in selected] == [
        PayloadKind.VALID,
        PayloadKind.MUTATED,
        PayloadKind.ATTACK,
    ]


def test_execute_mutations_does_not_imply_execute_attacks() -> None:
    selected = _graphql_payloads_selected_for_execution(
        valid_payloads=[_payload(PayloadKind.VALID)],
        mutation_payloads=[_payload(PayloadKind.MUTATED)],
        attack_payloads=[_payload(PayloadKind.ATTACK)],
        dry_run=False,
        execute_mutations=True,
        execute_attacks=False,
    )

    assert [payload.payload_kind for payload in selected] == [PayloadKind.VALID, PayloadKind.MUTATED]


def test_execute_attacks_does_not_imply_execute_mutations() -> None:
    selected = _graphql_payloads_selected_for_execution(
        valid_payloads=[_payload(PayloadKind.VALID)],
        mutation_payloads=[_payload(PayloadKind.MUTATED)],
        attack_payloads=[_payload(PayloadKind.ATTACK)],
        dry_run=False,
        execute_mutations=False,
        execute_attacks=True,
    )

    assert [payload.payload_kind for payload in selected] == [PayloadKind.VALID, PayloadKind.ATTACK]
