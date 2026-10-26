"""CloudFormation parameters for the stacks tarmac deploys, shared by the deploy phases and the dry-run plan."""

from ..core.config_loader import ConfigBundle

ROOT_SIGN_IN_REGION = "us-east-1"


def log_archive_parameters(
    bundle: ConfigBundle,
    org_id: str,
    management_account_id: str = "",
    audit_account_id: str = "",
    kept: frozenset[str] | set[str] = frozenset(),
) -> dict[str, str]:
    """Parameters for log-archive-hardening.yaml.

    ``management_account_id`` is needed only when AWS Config recorders are enabled: the log archive creates a
    separate bucket for Config history and lets the management account's recorder write to it.
    ``audit_account_id`` is needed only for GuardDuty findings export: its detectors may write to the bucket.
    ``kept`` is the stack's current resources: a Config or findings bucket already in it stays when the feature is
    turned off, with its policy; the recorders and the export are what turning it off removes. Both buckets are
    retained and have fixed names, so one dropped from the stack would block creating it again.
    """
    cloudtrail = bundle.org.cloudtrail
    config_bucket = bundle.org.security_services.config_recorder.enabled or "ConfigLogsBucket" in kept
    findings_bucket = exports_guardduty_findings(bundle) or "GuardDutyFindingsBucket" in kept
    params = {
        "OrganizationId": org_id,
        "OrgName": bundle.org.organization.name,
        "EnableKmsEncryption": "true" if cloudtrail.enable_kms else "false",
        "LogRetentionDays": str(cloudtrail.retention_days or 0),
        "EnableConfigDelivery": "true" if config_bucket else "false",
        "ManagementAccountId": management_account_id if config_bucket else "",
        "GuardDutyFindingsAccountId": audit_account_id if findings_bucket else "",
    }
    if cloudtrail.object_lock:
        params["ObjectLockMode"] = cloudtrail.object_lock.mode
        params["ObjectLockRetentionDays"] = str(cloudtrail.object_lock.retention_days)
    return params


def exports_guardduty_findings(bundle: ConfigBundle) -> bool:
    guardduty = bundle.org.security_services.guardduty
    return guardduty.enabled and guardduty.export_findings


def cloudtrail_parameters(
    bundle: ConfigBundle, log_archive_id: str, bucket_name: str, enable_kms: bool
) -> dict[str, str]:
    """Parameters for organization-cloudtrail.yaml."""
    return {
        "OrgName": bundle.org.organization.name,
        "LogArchiveAccountId": log_archive_id,
        "DestinationBucketName": bucket_name,
        "TrailName": bundle.org.cloudtrail.trail_name,
        "EnableKmsEncryption": "true" if enable_kms else "false",
    }


def backend_parameters(bundle: ConfigBundle, enable_dynamodb: bool) -> dict[str, str]:
    """Parameters for terraform-backend.yaml."""
    return {
        "OrgName": bundle.org.organization.name,
        "EnableDynamoDB": "true" if enable_dynamodb else "false",
        "DynamoDBTableName": bundle.org.terraform_backend.dynamodb_table_name,
    }


def audit_hardening_parameters(bundle: ConfigBundle, org_id: str) -> dict[str, str]:
    """Parameters for audit-account-hardening.yaml."""
    security_email = bundle.org.contacts.security.email
    params = {
        "OrgName": bundle.org.organization.name,
        "OrganizationId": org_id,
        "AlertEmail": str(security_email) if security_email else "",
    }
    webhook = bundle.org.security_services.incident_response_webhook_url
    if webhook:
        params["IncidentResponseWebhookUrl"] = str(webhook)
    return params


def root_alert_parameters(bundle: ConfigBundle) -> dict[str, str] | None:
    """Parameters for management-root-alert.yaml, or None when nobody is set to receive the alert."""
    email = str(bundle.org.contacts.security.email) if bundle.org.contacts.security.email else ""
    webhook = str(bundle.org.security_services.incident_response_webhook_url or "")
    if not email and not webhook:
        return None
    return {
        "OrgName": bundle.org.organization.name,
        "AlertEmail": email,
        "IncidentResponseWebhookUrl": webhook,
    }


def root_alert_regions(bundle: ConfigBundle, primary_region: str) -> list[str]:
    """us-east-1 for root sign-in events, the primary Region, and the declared Regions when asked for."""
    regions = [ROOT_SIGN_IN_REGION, primary_region]
    if bundle.org.security_services.root_alert.all_regions:
        regions.extend(bundle.org.organization.additional_regions)
    return list(dict.fromkeys(regions))


def config_recorder_regions(bundle: ConfigBundle, primary_region: str) -> list[str]:
    """Primary region first, then the additional regions, without repeats."""
    return list(dict.fromkeys([primary_region, *bundle.org.organization.additional_regions]))


def config_recorder_parameters(
    bundle: ConfigBundle, primary_region: str, bucket_name: str, kms_key_arn: str
) -> dict[str, str]:
    """Parameters for config-recorder.yaml (the management account stacks also get RecorderRoleArn)."""
    settings = bundle.org.security_services.config_recorder
    return {
        "DeliveryBucketName": bucket_name,
        "DeliveryKmsKeyArn": kms_key_arn,
        "GlobalResourcesRegion": primary_region,
        "IncludeGlobalResources": "true" if settings.include_global_resources else "false",
        "RecordResourceCompliance": "true" if settings.record_resource_compliance else "false",
        "RecordingFrequency": settings.recording_frequency,
    }


def object_lock_advice(bundle: ConfigBundle) -> str | None:
    """A `tarmac plan` note recommending Object Lock while it is off.

    S3 cannot switch Object Lock off once it is on, so tarmac never turns it on by itself.
    """
    if bundle.org.cloudtrail.object_lock is not None:
        return None
    return (
        "CloudTrail Object Lock is not configured, so anyone with delete rights on the log bucket can "
        "erase the audit trail. Best practice is `cloudtrail.object_lock: {mode: GOVERNANCE, "
        "retention_days: 365}`. Enable it before the first deploy if you can; S3 cannot turn it off "
        "again."
    )


def config_recorder_advice(bundle: ConfigBundle) -> str | None:
    """A `tarmac plan` note: Security Hub needs a Config recorder for most controls."""
    security = bundle.org.security_services
    if not security.securityhub.enabled or security.config_recorder.enabled:
        return None
    return (
        "Security Hub CSPM is enabled but AWS Config recording is not. Most of its controls need a Config "
        "recorder to be evaluated and report no data without one (unless the newer AWS Security Hub is also "
        "enabled, which manages its own recorder). Set `security_services.config_recorder.enabled: true` "
        "(billed per configuration item)."
    )
