"""HTTP execution package for YSLFuzz."""

from yslfuzz.execution.errors import (
    DestructiveMethodBlockedError,
    ExecutionError,
    InvalidRequestURLError,
    RequestBuildError,
    ScopeViolationError,
)
from yslfuzz.execution.executor import HttpExecutor
from yslfuzz.execution.request_builder import RequestBuilder
from yslfuzz.execution.scope import ScopeValidator
from yslfuzz.execution.session import merge_session_cookies, merge_session_headers

__all__ = [
    "DestructiveMethodBlockedError",
    "ExecutionError",
    "HttpExecutor",
    "InvalidRequestURLError",
    "RequestBuildError",
    "RequestBuilder",
    "ScopeValidator",
    "ScopeViolationError",
    "merge_session_cookies",
    "merge_session_headers",
]
