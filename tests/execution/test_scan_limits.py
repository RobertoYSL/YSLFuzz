import pytest

from yslfuzz.models import ScanLimits


def test_scan_limits_validates_safe_values() -> None:
    limits = ScanLimits(
        max_requests=10,
        max_requests_per_endpoint=2,
        max_duration_seconds=1.5,
        max_graphql_requests=5,
    )

    assert limits.max_requests == 10
    assert limits.max_requests_per_endpoint == 2


def test_scan_limits_rejects_negative_limits() -> None:
    with pytest.raises(ValueError):
        ScanLimits(max_requests=-1)

    with pytest.raises(ValueError):
        ScanLimits(max_duration_seconds=-0.1)

