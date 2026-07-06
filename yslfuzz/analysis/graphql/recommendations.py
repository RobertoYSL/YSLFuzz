"""Defensive recommendations for GraphQL detector findings."""

GRAPHQL_RECOMMENDATIONS: dict[str, str] = {
    "detector_graphql_error_disclosure": (
        "Normalize GraphQL error responses and keep stack traces, resolver details, and "
        "internal exception messages in protected logs."
    ),
    "detector_graphql_validation_bypass": (
        "Enforce GraphQL schema validation and resolver-level business validation before "
        "processing variables."
    ),
    "detector_graphql_introspection_exposure": (
        "Disable or restrict GraphQL introspection in production when it is not required."
    ),
    "detector_graphql_reflection": (
        "Avoid reflecting untrusted GraphQL variable values, or encode them for the response "
        "context before returning them."
    ),
    "detector_graphql_mass_assignment": (
        "Validate and reject unknown GraphQL input object fields, and use explicit allowlists "
        "for writable resolver fields."
    ),
    "detector_graphql_authorization_consistency": (
        "Enforce resolver-level authorization checks and compare behavior across configured "
        "authentication profiles."
    ),
    "detector_graphql_injection_marker": (
        "Parameterize data access, validate resolver inputs, and avoid passing user-controlled "
        "GraphQL values into database or system APIs."
    ),
    "detector_graphql_ssrf_marker": (
        "Validate URL-like GraphQL inputs server-side and block internal, link-local, and "
        "metadata destinations."
    ),
}


GRAPHQL_TITLES: dict[str, str] = {
    "detector_graphql_error_disclosure": "Possible GraphQL Error Disclosure",
    "detector_graphql_validation_bypass": "Possible GraphQL Validation Bypass",
    "detector_graphql_introspection_exposure": "Possible GraphQL Introspection Exposure",
    "detector_graphql_reflection": "Possible GraphQL Marker Reflection",
    "detector_graphql_mass_assignment": "Possible GraphQL Mass Assignment",
    "detector_graphql_authorization_consistency": "Possible GraphQL Broken Access Control",
    "detector_graphql_injection_marker": "Possible GraphQL Injection Marker Signal",
    "detector_graphql_ssrf_marker": "Possible GraphQL SSRF Handling Signal",
}

