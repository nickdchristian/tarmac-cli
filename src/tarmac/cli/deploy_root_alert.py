"""Phase 5 step: alert on root user activity in the management account."""

from pathlib import Path

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from ..services.cloudformation import CloudFormationService
from .ui import print_info, print_warning

ROOT_SIGN_IN_REGION = "us-east-1"
TEMPLATE_PATH = "cloudformation/management-root-alert.yaml"


def root_alert_regions(bundle: ConfigBundle, primary_region: str) -> list[str]:
    """us-east-1 for root sign-in events, the primary Region, and the declared Regions when asked for."""
    regions = [ROOT_SIGN_IN_REGION, primary_region]
    if bundle.org.security_services.root_alert.all_regions:
        regions.extend(bundle.org.organization.additional_regions)
    return list(dict.fromkeys(regions))


def deploy_management_root_alert(
    session_mgr: AwsSessionManager,
    cfn_service: CloudFormationService,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Deploy the root activity alert to the management account in each Region it watches."""
    settings = bundle.org.security_services.root_alert
    if not settings.enabled:
        return

    email = str(bundle.org.contacts.security.email) if bundle.org.contacts.security.email else ""
    webhook = bundle.org.security_services.incident_response_webhook_url or ""
    if not email and not webhook:
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
            {
                "OrgName": bundle.org.organization.name,
                "AlertEmail": email,
                "IncidentResponseWebhookUrl": webhook,
            },
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            dry_run=dry_run,
        )
