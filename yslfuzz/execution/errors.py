"""Execution-layer exceptions."""


class ExecutionError(RuntimeError):
    """Base class for execution engine failures."""


class RequestBuildError(ExecutionError):
    """Raised when an endpoint and payload cannot be converted into a request."""


class ScopeViolationError(ExecutionError):
    """Raised when a request is outside the configured scan scope."""


class DestructiveMethodBlockedError(ScopeViolationError):
    """Raised when a destructive HTTP method is disabled by configuration."""


class InvalidRequestURLError(ExecutionError):
    """Raised when a request URL is invalid."""
