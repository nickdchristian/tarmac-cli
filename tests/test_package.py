"""Package export tests."""


def test_package_exports():
    import tarmac
    import tarmac.core
    import tarmac.services

    assert hasattr(tarmac, "__version__")
    assert isinstance(tarmac.__version__, str)
    assert len(tarmac.__version__.split(".")) >= 3

    assert hasattr(tarmac.services, "SCPService")
    assert hasattr(tarmac.services, "PreflightService")
    assert hasattr(tarmac.services, "AccountService")
    assert hasattr(tarmac.services, "BaselineService")
    assert hasattr(tarmac.services, "CloudFormationService")
    assert hasattr(tarmac.services, "IdentityService")
    assert hasattr(tarmac.services, "OrganizationService")
    assert hasattr(tarmac.services, "OUService")
    assert hasattr(tarmac.services, "StatusService")
    assert hasattr(tarmac.services, "DriftService")
    assert hasattr(tarmac.services, "SecurityServicesService")

    assert hasattr(tarmac.core, "PreflightReport")
    assert hasattr(tarmac.core, "PreflightCheckResult")
    assert hasattr(tarmac.core, "PreflightCheckStatus")
    assert hasattr(tarmac.core, "SecurityServiceReport")
    assert hasattr(tarmac.core, "normalize_account_name")
    assert hasattr(tarmac.core, "AwsSessionManager")
    assert hasattr(tarmac.core, "load_all_configs")
