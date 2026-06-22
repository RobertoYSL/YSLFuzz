from yslfuzz.models import (
    ApiStyle,
    AttackCategory,
    AuthType,
    ConstraintType,
    ExecutionStatus,
    FieldType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    HttpMethod,
    ParameterLocation,
    PayloadKind,
    Protocol,
)


def test_documented_enum_values() -> None:
    assert [item.value for item in ApiStyle] == ["REST", "GRAPHQL", "UNKNOWN"]
    assert [item.value for item in Protocol] == ["HTTP", "HTTPS"]
    assert [item.value for item in HttpMethod] == [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    ]
    assert [item.value for item in ParameterLocation] == [
        "PATH",
        "QUERY",
        "HEADER",
        "COOKIE",
        "BODY",
        "GRAPHQL_VARIABLE",
        "GRAPHQL_ARGUMENT",
    ]
    assert [item.value for item in FieldType] == [
        "STRING",
        "INTEGER",
        "FLOAT",
        "BOOLEAN",
        "OBJECT",
        "ARRAY",
        "ENUM",
        "UUID",
        "EMAIL",
        "URI",
        "DATE",
        "DATETIME",
        "PASSWORD",
        "TOKEN",
        "FILE",
        "UNKNOWN",
    ]
    assert [item.value for item in AuthType] == [
        "NONE",
        "BASIC",
        "BEARER",
        "JWT",
        "API_KEY",
        "COOKIE",
        "OAUTH2",
        "CUSTOM",
    ]
    assert [item.value for item in ConstraintType] == [
        "REQUIRED",
        "MIN_LENGTH",
        "MAX_LENGTH",
        "MIN_VALUE",
        "MAX_VALUE",
        "REGEX",
        "ENUM",
        "FORMAT",
        "DEFAULT",
        "NULLABLE",
        "UNIQUE",
        "READ_ONLY",
        "WRITE_ONLY",
    ]
    assert [item.value for item in PayloadKind] == [
        "VALID",
        "BOUNDARY",
        "MUTATED",
        "ATTACK",
        "INVALID",
        "CONTROL",
    ]
    assert [item.value for item in AttackCategory] == [
        "SQL_INJECTION",
        "NOSQL_INJECTION",
        "COMMAND_INJECTION",
        "SSRF",
        "XSS",
        "MASS_ASSIGNMENT",
        "BROKEN_ACCESS_CONTROL",
        "GRAPHQL_DEPTH_ABUSE",
        "GRAPHQL_INTROSPECTION_ABUSE",
        "GRAPHQL_BATCHING_ABUSE",
        "AUTH_BYPASS",
        "INPUT_VALIDATION",
        "INFORMATION_DISCLOSURE",
    ]
    assert [item.value for item in ExecutionStatus] == [
        "PENDING",
        "RUNNING",
        "COMPLETED",
        "FAILED",
        "SKIPPED",
        "TIMEOUT",
        "BLOCKED",
    ]
    assert [item.value for item in FindingSeverity] == [
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]
    assert [item.value for item in FindingConfidence] == ["LOW", "MEDIUM", "HIGH", "CONFIRMED"]
    assert [item.value for item in FindingStatus] == [
        "OPEN",
        "CONFIRMED",
        "FALSE_POSITIVE",
        "IGNORED",
        "FIXED",
    ]
