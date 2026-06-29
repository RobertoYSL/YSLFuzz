"""Attack execution planning with explicit opt-in safety gates."""

from collections.abc import Sequence

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel, prefixed_id
from yslfuzz.models.enums import AttackCategory, PayloadKind
from yslfuzz.models.payload import PayloadCandidate
from yslfuzz.models.schema import Endpoint


class AttackExecutionConfig(YSLFuzzModel):
    """Explicit opt-in configuration for attack payload execution."""

    enabled: bool = False
    enabled_categories: list[AttackCategory] = Field(default_factory=list)
    max_attack_requests_per_endpoint: int = 5
    require_explicit_authorization: bool = True
    allow_sensitive_fields: bool = False
    execute_only_safe_probes: bool = True
    dry_run: bool = False


class AttackExecutionPlan(YSLFuzzModel):
    """Deterministic set of attack payloads approved for execution."""

    attack_execution_plan_id: str = Field(default_factory=lambda: prefixed_id("attack_plan"))
    endpoint_id: str
    payloads: list[PayloadCandidate] = Field(default_factory=list)
    blocked_reasons: list[str] = Field(default_factory=list)


class AttackExecutionPlanner:
    """Filter generated attack payloads according to explicit attack execution policy."""

    def __init__(self, config: AttackExecutionConfig | None = None) -> None:
        self.config = config or AttackExecutionConfig()

    def plan(
        self,
        endpoint: Endpoint,
        valid_payloads: Sequence[PayloadCandidate],
        attack_payloads: Sequence[PayloadCandidate],
    ) -> AttackExecutionPlan:
        """Return attack payloads approved for execution."""
        blocked_reasons: list[str] = []
        if not self.config.enabled:
            return AttackExecutionPlan(
                endpoint_id=endpoint.endpoint_id,
                blocked_reasons=["attack execution disabled"],
            )
        if self.config.dry_run:
            return AttackExecutionPlan(
                endpoint_id=endpoint.endpoint_id,
                blocked_reasons=["dry-run prevents attack execution"],
            )
        if self.config.require_explicit_authorization and not self.config.enabled:
            return AttackExecutionPlan(
                endpoint_id=endpoint.endpoint_id,
                blocked_reasons=["explicit authorization required"],
            )

        valid_ids = {payload.payload_id for payload in valid_payloads}
        selected: list[PayloadCandidate] = []
        for payload in sorted(attack_payloads, key=lambda candidate: candidate.payload_id):
            if len(selected) >= self.config.max_attack_requests_per_endpoint:
                break
            reason = self._blocked_reason(payload, valid_ids)
            if reason is not None:
                blocked_reasons.append(reason)
                continue
            selected.append(payload)

        return AttackExecutionPlan(
            endpoint_id=endpoint.endpoint_id,
            payloads=selected,
            blocked_reasons=blocked_reasons,
        )

    def _blocked_reason(
        self,
        payload: PayloadCandidate,
        valid_payload_ids: set[str],
    ) -> str | None:
        if payload.payload_kind != PayloadKind.ATTACK:
            return f"{payload.payload_id}: payload is not ATTACK kind"
        if payload.attack_category is None:
            return f"{payload.payload_id}: attack_category missing"
        if self.config.enabled_categories and payload.attack_category not in self.config.enabled_categories:
            return f"{payload.payload_id}: category disabled"
        if payload.parent_payload_id is not None and payload.parent_payload_id not in valid_payload_ids:
            return f"{payload.payload_id}: parent valid payload not present"
        if self.config.execute_only_safe_probes and not bool(payload.metadata.get("non_executing")):
            return f"{payload.payload_id}: unsafe probe metadata"
        if not self.config.allow_sensitive_fields and bool(payload.metadata.get("target_sensitive")):
            return f"{payload.payload_id}: sensitive target blocked"
        return None
