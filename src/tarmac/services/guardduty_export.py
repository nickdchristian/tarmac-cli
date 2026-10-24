"""GuardDuty findings export from the delegated administrator to the log archive's findings bucket."""

from dataclasses import dataclass
from typing import Any

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.stack_names import Stack
from .cloudformation import CloudFormationService
from .stack_parameters import exports_guardduty_findings

CREATE = "CREATE"
UPDATE = "UPDATE"
DELETE = "DELETE"
NO_CHANGE = "NO CHANGE"


@dataclass(frozen=True)
class FindingsExport:
    """Where the audit account's detectors publish findings. An empty ``bucket_arn`` turns export off."""

    org_name: str
    bucket_arn: str = ""
    kms_key_arn: str = ""
    bucket_owner: str = ""

    def owns(self, destination_arn: str) -> bool:
        """True for the findings bucket tarmac creates (log-archive-hardening.yaml names it)."""
        return f":::{self.org_name}-guardduty-findings-" in destination_arn


def findings_export(
    session_mgr: AwsSessionManager, bundle: ConfigBundle, region: str, accts: dict[str, str]
) -> FindingsExport | None:
    """The export the config asks for: off, the log archive's findings bucket, or None while that bucket is missing."""
    org_name = bundle.org.organization.name
    if not exports_guardduty_findings(bundle):
        return FindingsExport(org_name)
    log_archive_id = bundle.resolve_account_id(bundle.get_log_archive_account_name() or "log-archive", accts)
    if not log_archive_id:
        return None
    outputs = CloudFormationService(session_mgr)._fetch_stack_outputs(
        session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=region),
        Stack.LOG_ARCHIVE.for_org(org_name),
    )
    bucket_arn = outputs.get("GuardDutyFindingsBucketArn", "")
    if not bucket_arn:
        return None
    return FindingsExport(org_name, bucket_arn, outputs.get("GuardDutyFindingsKmsKeyArn", ""), log_archive_id)


def _s3_destinations(gd: Any, detector_id: str) -> list[tuple[str, dict[str, str]]]:
    found = []
    for dest in gd.list_publishing_destinations(DetectorId=detector_id).get("Destinations", []):
        if dest.get("DestinationType") != "S3":
            continue
        props = gd.describe_publishing_destination(
            DetectorId=detector_id, DestinationId=dest["DestinationId"]
        ).get("DestinationProperties", {})
        found.append((str(dest["DestinationId"]), props))
    return found


def reconcile_findings_export(
    gd: Any, detector_id: str, export: FindingsExport, region: str, dry_run: bool = False
) -> str:
    """Point the detector's S3 export at the findings bucket, or remove tarmac's export when it is off.

    A detector has one S3 destination, so with export on an existing one is repointed. With export off only a
    destination at tarmac's bucket is deleted; one the organization set up elsewhere is left alone. Findings
    already in the bucket stay there. Returns the plan action.
    """
    destinations = _s3_destinations(gd, detector_id)
    resource = f"guardduty-export:{detector_id}:{region}"
    if not export.bucket_arn:
        ours = [dest_id for dest_id, props in destinations if export.owns(props.get("DestinationArn", ""))]
        for dest_id in ours:
            if not dry_run:
                gd.delete_publishing_destination(DetectorId=detector_id, DestinationId=dest_id)
            audit(
                "delete",
                resource,
                Outcome.SUCCEEDED,
                f"Stopped exporting GuardDuty findings in {region}; exported findings stay in the bucket",
                dry_run=dry_run,
                region=region,
            )
        return DELETE if ours else NO_CHANGE

    wanted = {
        "DestinationArn": export.bucket_arn,
        "KmsKeyArn": export.kms_key_arn,
        "ExpectedBucketOwner": export.bucket_owner,
    }
    message = f"GuardDuty findings in {region} to {export.bucket_arn.rsplit(':', 1)[-1]}"
    if not destinations:
        if not dry_run:
            gd.create_publishing_destination(
                DetectorId=detector_id, DestinationType="S3", DestinationProperties=wanted
            )
        audit("create", resource, Outcome.SUCCEEDED, f"Exporting {message}", dry_run=dry_run, region=region)
        return CREATE

    dest_id, props = destinations[0]
    if all(props.get(key) == value for key, value in wanted.items()):
        return NO_CHANGE
    if not dry_run:
        gd.update_publishing_destination(
            DetectorId=detector_id, DestinationId=dest_id, DestinationProperties=wanted
        )
    audit("update", resource, Outcome.SUCCEEDED, f"Now exporting {message}", dry_run=dry_run, region=region)
    return UPDATE
