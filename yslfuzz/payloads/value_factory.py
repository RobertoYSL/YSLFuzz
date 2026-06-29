"""Schema-aware valid value generation for payload candidates."""

from datetime import UTC, date, datetime, timedelta
from random import Random
from typing import Any
from uuid import UUID

from yslfuzz.models.enums import ConstraintType, FieldType
from yslfuzz.models.schema import Constraint, FieldDefinition, Parameter


class ValueFactory:
    """Generate deterministic schema-valid values for supported field types."""

    def __init__(self, seed: int | None = None) -> None:
        self.seed = 0 if seed is None else seed
        self._random = Random(self.seed)

    def generate_for_field(self, field: FieldDefinition) -> Any:
        """Generate a schema-valid value for a field definition."""
        if field.example_value is not None:
            return field.example_value
        return self._generate(
            name=field.name,
            field_type=field.field_type,
            constraints=field.constraints,
            nullable=field.nullable,
            required=field.required,
            nested_fields=field.nested_fields,
            array_item_type=field.array_item_type.field_type if field.array_item_type else None,
            sensitive=field.sensitive,
        )

    def generate_for_parameter(self, parameter: Parameter) -> Any:
        """Generate a schema-valid value for a REST parameter."""
        if parameter.example_value is not None:
            return parameter.example_value
        if parameter.default_value is not None:
            return parameter.default_value
        return self._generate(
            name=parameter.name,
            field_type=parameter.field_type,
            constraints=parameter.constraints,
            nullable=False,
            required=parameter.required,
            nested_fields=[],
            array_item_type=None,
            sensitive=parameter.sensitive,
        )

    def _generate(
        self,
        *,
        name: str,
        field_type: FieldType,
        constraints: list[Constraint],
        nullable: bool,
        required: bool,
        nested_fields: list[FieldDefinition],
        array_item_type: FieldType | None,
        sensitive: bool,
    ) -> Any:
        if nullable and not required and self._random.choice([True, False]):
            return None

        enum_values = self._enum_values(constraints)
        if enum_values:
            return self._random.choice(enum_values)

        if sensitive:
            return self._string_value(name, constraints, prefix="synthetic-sensitive")

        if field_type in {FieldType.STRING, FieldType.UNKNOWN}:
            return self._string_value(name, constraints)
        if field_type == FieldType.INTEGER:
            return self._integer_value(constraints)
        if field_type == FieldType.FLOAT:
            return self._float_value(constraints)
        if field_type == FieldType.BOOLEAN:
            return self._random.choice([True, False])
        if field_type == FieldType.EMAIL:
            return f"user{self._random.randint(1000, 9999)}@example.test"
        if field_type == FieldType.UUID:
            return str(UUID(int=self._random.getrandbits(128)))
        if field_type == FieldType.URI:
            return f"https://example.test/resource/{self._random.randint(1000, 9999)}"
        if field_type == FieldType.DATE:
            return (date(2024, 1, 1) + timedelta(days=self._random.randint(0, 365))).isoformat()
        if field_type == FieldType.DATETIME:
            base = datetime(2024, 1, 1, tzinfo=UTC)
            return (base + timedelta(seconds=self._random.randint(0, 86_400))).isoformat()
        if field_type == FieldType.OBJECT:
            return self._object_value(nested_fields)
        if field_type == FieldType.ARRAY:
            return [self._array_item_value(array_item_type, nested_fields)]
        if field_type == FieldType.ENUM:
            return self._string_value(name, constraints)

        return self._string_value(name, constraints)

    def _object_value(self, fields: list[FieldDefinition]) -> dict[str, Any]:
        return {
            field.name: self.generate_for_field(field)
            for field in fields
            if field.required or not field.read_only
        }

    def _array_item_value(
        self,
        array_item_type: FieldType | None,
        nested_fields: list[FieldDefinition],
    ) -> Any:
        if array_item_type == FieldType.OBJECT:
            return self._object_value(nested_fields)
        if array_item_type is None:
            return self._string_value("item", [])
        return self._generate(
            name="item",
            field_type=array_item_type,
            constraints=[],
            nullable=False,
            required=True,
            nested_fields=[],
            array_item_type=None,
            sensitive=False,
        )

    def _string_value(
        self,
        name: str,
        constraints: list[Constraint],
        prefix: str = "value",
    ) -> str:
        min_length = max(1, self._int_constraint(constraints, ConstraintType.MIN_LENGTH, 1))
        max_length = self._int_constraint(constraints, ConstraintType.MAX_LENGTH, max(32, min_length))
        max_length = max(min_length, max_length)

        random_suffix = str(self._random.randint(1000, 9999))
        base = f"{prefix}-{self._safe_name(name)}-{random_suffix}"
        if len(base) <= max_length:
            value = base
        else:
            compact = f"{prefix}-{random_suffix}"
            value = compact if len(compact) <= max_length else random_suffix[-max_length:]

        if len(value) < min_length:
            value = value + ("x" * (min_length - len(value)))
        return value[:max_length]

    def _integer_value(self, constraints: list[Constraint]) -> int:
        minimum = self._int_constraint(constraints, ConstraintType.MIN_VALUE, 1)
        maximum = self._int_constraint(constraints, ConstraintType.MAX_VALUE, minimum + 100)
        maximum = max(minimum, maximum)
        return self._random.randint(minimum, maximum)

    def _float_value(self, constraints: list[Constraint]) -> float:
        minimum = self._float_constraint(constraints, ConstraintType.MIN_VALUE, 1.0)
        maximum = self._float_constraint(constraints, ConstraintType.MAX_VALUE, minimum + 100.0)
        maximum = max(minimum, maximum)
        value = self._random.uniform(minimum, maximum)
        return round(value, 6)

    def _enum_values(self, constraints: list[Constraint]) -> list[Any]:
        for constraint in constraints:
            if constraint.constraint_type == ConstraintType.ENUM and isinstance(constraint.value, list):
                return constraint.value
        return []

    def _int_constraint(
        self,
        constraints: list[Constraint],
        constraint_type: ConstraintType,
        default: int,
    ) -> int:
        for constraint in constraints:
            if constraint.constraint_type == constraint_type and isinstance(constraint.value, int):
                return constraint.value
        return default

    def _float_constraint(
        self,
        constraints: list[Constraint],
        constraint_type: ConstraintType,
        default: float,
    ) -> float:
        for constraint in constraints:
            if constraint.constraint_type == constraint_type and isinstance(
                constraint.value,
                int | float,
            ):
                return float(constraint.value)
        return default

    def _safe_name(self, name: str) -> str:
        normalized = "".join(character.lower() if character.isalnum() else "-" for character in name)
        return normalized.strip("-") or "field"
