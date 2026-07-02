"""Validation helpers for merged scan configuration profiles."""

from yslfuzz.config.models import ScanConfig


class ConfigValidationError(ValueError):
    """Raised when a scan configuration profile violates safety gates."""


class ConfigValidator:
    """Validate post-merge safety gates."""

    def validate(self, config: ScanConfig) -> None:
        """Validate authorization gates for execution features."""
        execution = config.execution
        safety = config.safety
        if (
            execution.execute_attacks
            and safety.require_authorization_for_attack_execution
            and not execution.i_understand_attack_execution_is_authorized
        ):
            raise ConfigValidationError(
                "execute_attacks requires i_understand_attack_execution_is_authorized"
            )
        if (
            execution.execute_mutations
            and safety.require_authorization_for_mutation_execution
            and not execution.i_understand_mutation_execution_is_authorized
        ):
            raise ConfigValidationError(
                "execute_mutations requires i_understand_mutation_execution_is_authorized"
            )
