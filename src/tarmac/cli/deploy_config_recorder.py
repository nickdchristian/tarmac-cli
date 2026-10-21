"""Phase 5 step: AWS Config recorders in every account (optional)."""

from pathlib import Path

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import GovernanceError
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from ..services.cloudformation import CloudFormationService
from ..services.config_recorder import ConfigRecorderService
from ..services.stack_parameters import (
    config_recorder_advice,
    config_recorder_parameters,
    config_recorder_regions,
)
from .ui import print_info, print_success, print_warning


def deploy_config_recorder(
    session_mgr: AwsSessionManager,
    cfn_service: CloudFormationService,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    accounts: dict[str, str],
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Deploy the recorder StackSet and management account stacks when ``config_recorder.enabled`` is set."""
    advice = config_recorder_advice(bundle)
    if advice:
        print_warning(advice)
    settings = bundle.org.security_services.config_recorder
    if not settings.enabled:
        return

    org_name = bundle.org.organization.name
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    log_archive_id = bundle.resolve_account_id(log_archive_name, accounts)
    if not log_archive_id:
        print_warning(
            f"Log archive account '{log_archive_name}' was not found among active accounts; "
            "skipping AWS Config recorders (they deliver to its bucket)."
        )
        return

    log_archive_cfn = session_mgr.get_member_client(
        log_archive_id, "cloudformation", region_name=target_region
    )
    outputs = cfn_service._fetch_stack_outputs(log_archive_cfn, Stack.LOG_ARCHIVE.for_org(org_name))
    bucket_name = outputs.get("ConfigBucketName", "")
    if not bucket_name:
        raise GovernanceError(
            "The log archive has no AWS Config bucket yet.",
            details=(
                "The bucket is created by the log archive stack (phase 3) when config_recorder is enabled. "
                "Run `tarmac deploy --phase 3` (or the full pipeline) first, then phase 5."
            ),
        )
    # The key output exists only when the log archive stack actually has the key, which is what the bucket needs.
    kms_key_arn = outputs.get("KmsKeyArn", "")

    regions = config_recorder_regions(bundle, target_region)
    print_info(f"Deploying AWS Config recorders to {len(regions)} Region(s) of every account...")
    report = ConfigRecorderService(session_mgr, cfn_service).deploy(
        org_name=org_name,
        template_file=resolve_resource_path("cloudformation/config-recorder.yaml", project_root=project_root),
        parameters=config_recorder_parameters(bundle, target_region, bucket_name, kms_key_arn),
        regions=regions,
        primary_region=target_region,
        management_account_id=str(session_mgr.get_caller_identity().get("Account", "")),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
    )
    if report.failures:
        raise GovernanceError(
            "Phase 5 failed: AWS Config recorders are not current in every account.",
            details="\n".join(report.failures),
        )
    print_success(
        f"AWS Config recorders: StackSet {report.stack_set_action.lower()}, "
        f"{len(report.management_stacks)} management account stack(s)."
    )
