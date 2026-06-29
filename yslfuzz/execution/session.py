"""Session state helpers for request construction."""

from collections.abc import Mapping
from typing import Any

from yslfuzz.models.execution import SessionState


def merge_session_headers(
    payload_headers: Mapping[str, Any],
    session_state: SessionState | None,
) -> dict[str, Any]:
    """Merge session headers with payload headers, preferring payload values."""
    headers = dict(session_state.headers) if session_state is not None else {}
    headers.update(payload_headers)
    return headers


def merge_session_cookies(
    payload_cookies: Mapping[str, Any],
    session_state: SessionState | None,
) -> dict[str, Any]:
    """Merge session cookies with payload cookies, preferring payload values."""
    cookies = dict(session_state.cookies) if session_state is not None else {}
    cookies.update(payload_cookies)
    return cookies
