"""Safe attack probe templates for controlled payload generation."""

from typing import Any

from pydantic import Field

from yslfuzz.models.base import YSLFuzzModel
from yslfuzz.models.enums import AttackCategory, FieldType, ParameterLocation


class AttackTemplate(YSLFuzzModel):
    """A safe, inert attack probe template."""

    name: str
    attack_category: AttackCategory
    target_field_types: list[FieldType]
    probe_value: Any
    safety_label: str
    description: str
    allowed_locations: list[ParameterLocation] = Field(
        default_factory=lambda: [
            ParameterLocation.BODY,
            ParameterLocation.QUERY,
            ParameterLocation.PATH,
            ParameterLocation.HEADER,
        ]
    )
    input_validation_only_for_enum: bool = False


def default_attack_templates() -> list[AttackTemplate]:
    """Return deterministic safe probe templates for the MVP attack categories."""
    return [
        AttackTemplate(
            name="sqli_marker_string",
            attack_category=AttackCategory.SQL_INJECTION,
            target_field_types=[FieldType.STRING, FieldType.EMAIL, FieldType.UUID, FieldType.UNKNOWN],
            probe_value="yslfuzz_sqli_probe' OR 'yslfuzz_probe'='yslfuzz_probe",
            safety_label="inert_sql_parser_probe",
            description="Low-risk SQL parser/anomaly marker; no destructive query.",
        ),
        AttackTemplate(
            name="nosql_marker_object",
            attack_category=AttackCategory.NOSQL_INJECTION,
            target_field_types=[FieldType.OBJECT, FieldType.STRING, FieldType.BOOLEAN, FieldType.UNKNOWN],
            probe_value={"yslfuzz_nosql_probe": "marker"},
            safety_label="inert_nosql_shape_probe",
            description="Controlled object-shape marker for NoSQL-like parsers.",
        ),
        AttackTemplate(
            name="command_marker_string",
            attack_category=AttackCategory.COMMAND_INJECTION,
            target_field_types=[FieldType.STRING, FieldType.UNKNOWN],
            probe_value="yslfuzz_cmd_probe",
            safety_label="inert_command_marker",
            description="Marker only; does not invoke shell syntax or utilities.",
        ),
        AttackTemplate(
            name="ssrf_invalid_uri",
            attack_category=AttackCategory.SSRF,
            target_field_types=[FieldType.URI, FieldType.STRING, FieldType.UNKNOWN],
            probe_value="https://yslfuzz-ssrf-probe.invalid/resource",
            safety_label="reserved_invalid_domain",
            description="Reserved non-production .invalid URI marker.",
        ),
        AttackTemplate(
            name="xss_inert_markup",
            attack_category=AttackCategory.XSS,
            target_field_types=[FieldType.STRING, FieldType.EMAIL, FieldType.UNKNOWN],
            probe_value="<yslfuzz_xss_probe inert='true'>marker</yslfuzz_xss_probe>",
            safety_label="inert_markup_marker",
            description="Inert markup-like marker; no executable script tag.",
        ),
        AttackTemplate(
            name="mass_assignment_extra_fields",
            attack_category=AttackCategory.MASS_ASSIGNMENT,
            target_field_types=[FieldType.OBJECT, FieldType.UNKNOWN],
            probe_value={
                "yslfuzz_probe": "mass_assignment_marker",
                "yslfuzz_extra_role": "controlled_marker",
            },
            safety_label="controlled_extra_fields",
            description="Adds controlled extra fields with yslfuzz names only.",
        ),
        AttackTemplate(
            name="broken_access_control_marker",
            attack_category=AttackCategory.BROKEN_ACCESS_CONTROL,
            target_field_types=[FieldType.STRING, FieldType.UUID, FieldType.INTEGER, FieldType.UNKNOWN],
            probe_value="yslfuzz_bac_probe",
            safety_label="metadata_only_access_control_marker",
            description="Classification marker for future authorization checks; not an auth bypass.",
        ),
        AttackTemplate(
            name="input_validation_string_boundary",
            attack_category=AttackCategory.INPUT_VALIDATION,
            target_field_types=[FieldType.STRING, FieldType.EMAIL, FieldType.UUID, FieldType.ENUM, FieldType.UNKNOWN],
            probe_value="yslfuzz_input_validation_probe",
            safety_label="controlled_input_validation_marker",
            description="Controlled type/format validation marker.",
            input_validation_only_for_enum=True,
        ),
        AttackTemplate(
            name="input_validation_numeric_boundary",
            attack_category=AttackCategory.INPUT_VALIDATION,
            target_field_types=[FieldType.INTEGER, FieldType.FLOAT],
            probe_value=-1,
            safety_label="controlled_numeric_boundary",
            description="Small numeric boundary marker.",
        ),
        AttackTemplate(
            name="input_validation_boolean_flip",
            attack_category=AttackCategory.INPUT_VALIDATION,
            target_field_types=[FieldType.BOOLEAN],
            probe_value=None,
            safety_label="controlled_boolean_flip",
            description="Boolean flip validation marker.",
        ),
        AttackTemplate(
            name="information_disclosure_marker",
            attack_category=AttackCategory.INFORMATION_DISCLOSURE,
            target_field_types=[FieldType.STRING, FieldType.UNKNOWN],
            probe_value="yslfuzz_info_disclosure_probe",
            safety_label="inert_information_disclosure_marker",
            description="Marker for future information disclosure differentials.",
        ),
    ]
