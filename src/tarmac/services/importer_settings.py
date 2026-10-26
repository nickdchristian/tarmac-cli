"""The settings `tarmac import` reads from what is running, so the imported config plans with no changes.

The structure (OUs, accounts, SCPs, identity) comes from Organizations and Identity Center. Everything here is a
setting: what tarmac's own stacks were deployed with, and which security services run. A setting that can't be read
is left at its default and named in a TODO, because a default that is off makes the next deploy turn the thing off.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.stack_names import Stack
from .baseline_stacks import stack_set_name
from .security import GUARDDUTY_FEATURE_FLAGS
from .security_central import POLICY_NAME

logger = logging.getLogger(__name__)

_READ_ERRORS = (ClientError, BotoCoreError)


def standard_name(arn: str) -> str:
    """``aws-foundational-security-best-practices/v/1.0.0`` from a standard's ARN, keeping the version running."""
    found = re.search(r"(?:standards|ruleset)/(.+)$", arn)
    return found.group(1) if found else arn


@dataclass
class Accounts:
    management: str
    audit: str | None
    log_archive: str | None
    deployment: str | None


@dataclass
class LiveSettings:
    """Reads one organization's settings. ``write(path, text)`` writes a file next to the config."""

    session_mgr: AwsSessionManager
    region: str
    org_name: str
    accounts: Accounts
    ou_names: dict[str, str]  # {OU or root ID: name}, the root as "root"
    project_root: Path
    write: Callable[[Path, str], None]
    todos: list[str] = field(default_factory=list)

    def read(self) -> dict[str, Any]:
        """organization.yaml sections, to merge over the structural import."""
        settings: dict[str, Any] = {"cloudtrail": {}, "terraform_backend": {}, "security_services": {}}
        log_archive = self._stack_parameters(self.accounts.log_archive, Stack.LOG_ARCHIVE)
        if log_archive:
            settings["cloudtrail"].update(self._cloudtrail(log_archive))
        backend = self._stack_parameters(self.accounts.deployment, Stack.TERRAFORM_BACKEND)
        if backend:
            settings["terraform_backend"]["enable_dynamodb"] = backend.get("EnableDynamoDB") == "true"
            if backend.get("DynamoDBTableName"):
                settings["terraform_backend"]["dynamodb_table_name"] = backend["DynamoDBTableName"]
        audit_stack = self._stack_parameters(self.accounts.audit, Stack.AUDIT_ACCOUNT)
        if audit_stack.get("IncidentResponseWebhookUrl"):
            settings["security_services"]["incident_response_webhook_url"] = audit_stack[
                "IncidentResponseWebhookUrl"
            ]

        regions: set[str] = set()
        config_recorder, recorder_regions = self._config_recorder()
        if config_recorder:
            settings["security_services"]["config_recorder"] = config_recorder
            regions |= recorder_regions
        if self.accounts.audit:
            guardduty = self._guardduty(
                self.accounts.audit, bool(log_archive.get("GuardDutyFindingsAccountId"))
            )
            if guardduty:
                settings["security_services"]["guardduty"] = guardduty
            securityhub, linked = self._securityhub(self.accounts.audit)
            if securityhub:
                settings["security_services"]["securityhub"] = securityhub
                regions |= linked
        settings["additional_regions"] = sorted(regions - {self.region})
        settings["baseline_stacks"] = self._baseline_stacks()
        settings["cost_allocation_tags"] = self._cost_allocation_tags()
        return settings

    def _could_not(self, what: str, exc: Exception) -> None:
        self.todos.append(
            f"Could not read {what} ({exc}). It was left at its default: check it before deploying."
        )

    def _cfn(self, account_id: str | None, region: str | None = None) -> Any:
        region = region or self.region
        if not account_id or account_id == self.accounts.management:
            return self.session_mgr.get_client("cloudformation", region_name=region)
        return self.session_mgr.get_member_client(account_id, "cloudformation", region_name=region)

    def _stack_parameters(self, account_id: str | None, stack: Stack) -> dict[str, str]:
        """The parameters tarmac's stack was last deployed with; {} when it doesn't exist."""
        if not account_id:
            return {}
        name = stack.for_org(self.org_name)
        try:
            found = self._cfn(account_id).describe_stacks(StackName=name)["Stacks"]
        except ClientError as exc:
            if "does not exist" not in str(exc):
                self._could_not(f"stack {name}", exc)
            return {}
        except BotoCoreError as exc:
            self._could_not(f"stack {name}", exc)
            return {}
        return {
            str(p["ParameterKey"]): str(p.get("ParameterValue", "")) for p in found[0].get("Parameters", [])
        }

    @staticmethod
    def _cloudtrail(parameters: dict[str, str]) -> dict[str, Any]:
        cloudtrail: dict[str, Any] = {"enable_kms": parameters.get("EnableKmsEncryption") == "true"}
        days = int(parameters.get("LogRetentionDays") or 0)
        if days:
            cloudtrail["retention_days"] = days
        if parameters.get("ObjectLockMode"):
            cloudtrail["object_lock"] = {
                "mode": parameters["ObjectLockMode"],
                "retention_days": int(parameters.get("ObjectLockRetentionDays") or 1),
            }
        return cloudtrail

    def _config_recorder(self) -> tuple[dict[str, Any], set[str]]:
        """Tarmac's recorder StackSet: its settings, and the Regions it records in."""
        cf = self._cfn(None)
        name = Stack.CONFIG_RECORDER.for_org(self.org_name)
        try:
            stack_set = cf.describe_stack_set(StackSetName=name)["StackSet"]
            regions = {
                str(i["Region"])
                for page in cf.get_paginator("list_stack_instances").paginate(StackSetName=name)
                for i in page.get("Summaries", [])
            }
        except ClientError as exc:
            if "StackSetNotFound" not in str(exc):
                self._could_not(f"StackSet {name}", exc)
            return {}, set()
        except BotoCoreError as exc:
            self._could_not(f"StackSet {name}", exc)
            return {}, set()
        p = {
            str(x["ParameterKey"]): str(x.get("ParameterValue", "")) for x in stack_set.get("Parameters", [])
        }
        settings: dict[str, Any] = {"enabled": True}
        if "IncludeGlobalResources" in p:
            settings["include_global_resources"] = p["IncludeGlobalResources"] == "true"
        if "RecordResourceCompliance" in p:
            settings["record_resource_compliance"] = p["RecordResourceCompliance"] == "true"
        if p.get("RecordingFrequency"):
            settings["recording_frequency"] = p["RecordingFrequency"]
        return settings, regions

    def _delegated(self, service: str, audit_id: str) -> bool:
        admins = self.session_mgr.get_client(
            service, region_name=self.region
        ).list_organization_admin_accounts()
        key = "AdminAccountId" if service == "guardduty" else "AccountId"
        return any(a.get(key) == audit_id for a in admins.get("AdminAccounts", []))

    def _guardduty(self, audit_id: str, exports_findings: bool) -> dict[str, Any]:
        """GuardDuty as the audit account runs it: on when delegated to it, with its detector's protection plans."""
        try:
            if not self._delegated("guardduty", audit_id):
                return {}
            gd = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=self.region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            features = gd.get_detector(DetectorId=detectors[0]).get("Features", []) if detectors else []
        except _READ_ERRORS as exc:
            self._could_not("GuardDuty", exc)
            return {}
        enabled = {str(f.get("Name")) for f in features if f.get("Status") == "ENABLED"}
        return {
            "enabled": True,
            "export_findings": exports_findings,
            "features": {flag: name in enabled for name, flag in GUARDDUTY_FEATURE_FLAGS.items()},
        }

    def _securityhub(self, audit_id: str) -> tuple[dict[str, Any], set[str]]:
        """Security Hub as the audit account runs it, and the Regions linked to its home Region."""
        try:
            if not self._delegated("securityhub", audit_id):
                return {}, set()
            sh = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=self.region)
            central = (
                sh.describe_organization_configuration()
                .get("OrganizationConfiguration", {})
                .get("ConfigurationType")
                == "CENTRAL"
            )
            arns = self._central_standards(sh) if central else None
            if arns is None:
                central = False
                arns = [
                    str(s["StandardsArn"])
                    for s in sh.get_enabled_standards().get("StandardsSubscriptions", [])
                    if s.get("StandardsStatus") in ("READY", "PENDING", "INCOMPLETE")
                ]
            linked: set[str] = set()
            for aggregator in sh.list_finding_aggregators().get("FindingAggregators", []):
                detail = sh.get_finding_aggregator(FindingAggregatorArn=aggregator["FindingAggregatorArn"])
                linked |= {str(r) for r in detail.get("Regions", [])}
        except _READ_ERRORS as exc:
            self._could_not("Security Hub", exc)
            return {}, set()
        settings = {
            "enabled": True,
            "central_configuration": central,
            "standards": sorted(standard_name(a) for a in arns),
        }
        return settings, linked

    @staticmethod
    def _central_standards(sh: Any) -> list[str] | None:
        """The standards in tarmac's configuration policy, or None when the organization uses someone else's."""
        for page in sh.get_paginator("list_configuration_policies").paginate():
            for summary in page.get("ConfigurationPolicySummaries", []):
                if summary.get("Name") == POLICY_NAME:
                    policy = sh.get_configuration_policy(Identifier=summary["Id"])
                    service = policy.get("ConfigurationPolicy", {}).get("SecurityHub", {})
                    return [str(a) for a in service.get("EnabledStandardIdentifiers", [])]
        return None

    def _baseline_stacks(self) -> list[dict[str, Any]]:
        """Tarmac's baseline StackSets, with their templates written out: left out, a deploy would delete them."""
        cf = self._cfn(None)
        prefix = stack_set_name(self.org_name, "")
        stacks: list[dict[str, Any]] = []
        try:
            names = sorted(
                str(s["StackSetName"])
                for page in cf.get_paginator("list_stack_sets").paginate(Status="ACTIVE")
                for s in page.get("Summaries", [])
                if str(s["StackSetName"]).startswith(prefix)
            )
            for name in names:
                stack_set = cf.describe_stack_set(StackSetName=name)["StackSet"]
                regions = sorted(
                    {
                        str(i["Region"])
                        for page in cf.get_paginator("list_stack_instances").paginate(StackSetName=name)
                        for i in page.get("Summaries", [])
                    }
                )
                short = name[len(prefix) :]
                targets = [
                    self.ou_names.get(str(ou), str(ou)) for ou in stack_set.get("OrganizationalUnitIds", [])
                ]
                if not regions or not targets:
                    self.todos.append(
                        f"Baseline StackSet '{name}' has no stack instances to read its OUs and Regions from. It "
                        "was not imported, so a deploy would delete it: add it to baseline_stacks yourself."
                    )
                    continue
                rel = f"baseline/{short}.yaml"
                target = self.project_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                self.write(target, str(stack_set.get("TemplateBody", "")))
                stacks.append(
                    {
                        "name": short,
                        "template_file": rel,
                        "target_ous": sorted(targets),
                        "regions": regions,
                        "parameters": {
                            str(p["ParameterKey"]): str(p.get("ParameterValue", ""))
                            for p in stack_set.get("Parameters", [])
                        },
                    }
                )
        except _READ_ERRORS as exc:
            self._could_not("the baseline StackSets", exc)
        return stacks

    def _cost_allocation_tags(self) -> list[str]:
        """Active user-defined cost allocation tags: a deploy turns off the ones tarmac turned on and no longer
        finds in the config."""
        try:
            ce = self.session_mgr.get_client("ce", region_name="us-east-1")
            tags: list[str] = []
            token: str | None = None
            while True:
                page = ce.list_cost_allocation_tags(
                    Status="Active", Type="UserDefined", **({"NextToken": token} if token else {})
                )
                tags.extend(str(t["TagKey"]) for t in page.get("CostAllocationTags", []))
                token = page.get("NextToken")
                if not token:
                    return sorted(tags)
        except _READ_ERRORS as exc:
            self._could_not("the cost allocation tags", exc)
            return []
