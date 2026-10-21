"""Package export tests."""


def test_package_exports():
    import tarmac

    assert hasattr(tarmac, "__version__")
    assert isinstance(tarmac.__version__, str)
    assert len(tarmac.__version__.split(".")) >= 3
