"""Phase 5 step: alert on root user activity in the management account."""

from pathlib import Path

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from ..services.cloudformation import CloudFormationService
from ..services.stack_parameters import root_alert_parameters, root_alert_regions
from ..services.teardown import TeardownService
from .removals import apply_removals
from .ui import print_info, print_warning

TEMPLATE_PATH = "cloudformation/management-root-alert.yaml"


def deploy_management_root_alert(
    session_mgr: AwsSessionManager,
    cfn_service: CloudFormationService,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Deploy the root activity alert to the management account in each Region it watches."""
    settings = bundle.org.security_services.root_alert
    if not settings.enabled:
        apply_removals(
            "root activity alert", TeardownService(session_mgr).teardown_root_alert(bundle, target_region)
        )
        return

    parameters = root_alert_parameters(bundle)
    if parameters is None:
        print_warning(
            "Skipping the management account root activity alert: nobody is set to receive it. Set "
            "`contacts.security.email` (or `security_services.incident_response_webhook_url`), or "
            "`security_services.root_alert.enabled: false` to turn it off."
        )
        return

    regions = root_alert_regions(bundle, target_region)
    print_info(f"Deploying the management account root activity alert to {', '.join(regions)}...")
    template_file = resolve_resource_path(TEMPLATE_PATH, project_root=project_root)
    for region in regions:
        cfn_service.deploy_stack(
            session_mgr.get_client("cloudformation", region_name=region),
            Stack.ROOT_ALERT.for_org(bundle.org.organization.name),
            template_file,
            parameters,
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
        )
