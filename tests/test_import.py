import yslfuzz


def test_package_exposes_version() -> None:
    assert isinstance(yslfuzz.__version__, str)
    assert yslfuzz.__version__
