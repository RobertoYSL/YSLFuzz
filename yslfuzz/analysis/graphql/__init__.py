"""GraphQL-specific conservative analysis APIs."""

from yslfuzz.analysis.graphql.config import GraphQLAnalysisConfig
from yslfuzz.analysis.graphql.detectors import (
    GraphQLAuthorizationConsistencyDetector,
    GraphQLErrorDisclosureDetector,
    GraphQLInjectionMarkerDetector,
    GraphQLIntrospectionExposureDetector,
    GraphQLMassAssignmentDetector,
    GraphQLReflectionDetector,
    GraphQLResponseDetector,
    GraphQLSSRFMarkerDetector,
    GraphQLValidationBypassDetector,
    default_graphql_detectors,
)
from yslfuzz.analysis.graphql.engine import GraphQLAnalysisEngine

__all__ = [
    "GraphQLAnalysisConfig",
    "GraphQLAnalysisEngine",
    "GraphQLAuthorizationConsistencyDetector",
    "GraphQLErrorDisclosureDetector",
    "GraphQLInjectionMarkerDetector",
    "GraphQLIntrospectionExposureDetector",
    "GraphQLMassAssignmentDetector",
    "GraphQLReflectionDetector",
    "GraphQLResponseDetector",
    "GraphQLSSRFMarkerDetector",
    "GraphQLValidationBypassDetector",
    "default_graphql_detectors",
]

