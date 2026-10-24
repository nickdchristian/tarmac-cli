"""Security Hub central configuration: one policy, applied to the whole organization from the home Region.

With local configuration (the old behaviour) new member accounts join Security Hub with no standards, and every Region
is configured one call at a time. With central configuration the delegated administrator defines a configuration
policy (Security Hub on, these standards) and associates it with the organization root, so existing and new accounts
in the home and linked Regions get the same setup. Policies can only be managed from the home Region, which is also
the finding aggregation Region.
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from ..core.adoption import ADOPT_HINT, adopt_existing
from ..core.audit import Outcome, audit
from ..core.aws_audit import retry_notice, retrying
from ..core.exceptions import GovernanceError

logger = logging.getLogger(__name__)

POLICY_NAME = "tarmac-security-baseline"
# What GetConfigurationPolicyAssociation reports for a target that is not under a configuration policy.
SELF_MANAGED = "SELF_MANAGED_SECURITY_HUB"


def resolve_standard_arn(available: list[dict[str, Any]], desired: str) -> str:
    """Find the ARN of a standard from a name like ``aws-foundational-security-best-practices``."""
    norm_desired = desired.lower().replace("_", "-")
    for std in available:
        std_arn = str(std.get("StandardsArn", ""))
        if norm_desired in std_arn.lower() or norm_desired in str(std.get("Name", "")).lower():
            return std_arn
    raise GovernanceError(
        f"Unknown Security Hub standard '{desired}'.",
        details="Check security_services.securityhub.standards in organization.yaml.",
    )


class SecurityHubCentralConfiguration:
    """Switches the organization to central configuration and keeps one baseline policy on the root."""

    def __init__(
        self,
        sh: Any,
        *,
        policy_name: str,
        standards: list[str],
        root_id: str,
        sleep: Callable[[float], None] = time.sleep,
        timeout_seconds: float = 180.0,
    ) -> None:
        self.sh = sh
        self.policy_name = policy_name
        self.standards = standards
        self.root_id = root_id
        self._sleep = sleep
        self._timeout = timeout_seconds

    def apply(self) -> None:
        self._enable_central_mode()
        policy_id = self._ensure_policy()
        self._ensure_association(policy_id)

    def _require_no_local_members(self) -> None:
        """Switching to central configuration makes the policy authoritative for member accounts.

        Accounts that already run Security Hub with their own standards may lose the ones the policy does not list;
        the AWS documentation does not say what happens to them, so do not do it to an existing setup unasked.
        """
        if adopt_existing():
            return
        members = self.sh.list_members(OnlyAssociated=True, MaxResults=1).get("Members", [])
        if members:
            raise GovernanceError(
                "Security Hub already has member accounts configured one by one (local configuration).",
                details=(
                    "Switching the organization to central configuration lets one policy decide their standards, "
                    "which may turn off standards they enabled themselves. "
                    f"{ADOPT_HINT} Or set security_services.securityhub.central_configuration: false to keep "
                    "local configuration."
                ),
            )

    def _enable_central_mode(self) -> None:
        if self._configuration().get("ConfigurationType") != "CENTRAL":
            self._require_no_local_members()
            self._switch_to_central()
            audit(
                "configure",
                "securityhub:central-configuration",
                Outcome.SUCCEEDED,
                "Switched Security Hub to central configuration (policies managed from the home Region)",
            )
        self._wait_until_enabled()

    def _switch_to_central(self) -> None:
        """Security Hub refuses while it syncs the organization, for a few minutes after a new delegated admin."""
        waited = 0.0
        while True:
            try:
                with retrying():
                    self.sh.update_organization_configuration(
                        AutoEnable=False, OrganizationConfiguration={"ConfigurationType": "CENTRAL"}
                    )
                return
            except ClientError as e:
                if "still syncing" not in str(e) or waited >= self._timeout:
                    raise
            if not waited:
                retry_notice(
                    "Switching Security Hub to central configuration",
                    "it is still syncing the organization",
                    15.0,
                )
            self._sleep(15.0)
            waited += 15.0

    def _configuration(self) -> dict[str, Any]:
        return self.sh.describe_organization_configuration()["OrganizationConfiguration"]

    def _wait_until_enabled(self) -> None:
        waited = 0.0
        while True:
            config = self._configuration()
            status = str(config.get("Status", "ENABLED"))
            if status == "ENABLED":
                return
            if status == "FAILED":
                raise GovernanceError(
                    "Security Hub could not switch to central configuration.",
                    details=str(config.get("StatusMessage", "")),
                )
            if waited >= self._timeout:
                raise GovernanceError(
                    "Security Hub central configuration is still PENDING.",
                    details=f"Waited {int(waited)}s. Re-run once its status is ENABLED.",
                )
            self._sleep(5.0)
            waited += 5.0

    def _desired_policy(self) -> dict[str, Any]:
        available = self.sh.describe_standards().get("Standards", [])
        arns = sorted({resolve_standard_arn(available, s) for s in self.standards})
        # Disabling no controls enables all of them in the chosen standards, including ones AWS releases later.
        return {
            "SecurityHub": {
                "ServiceEnabled": True,
                "EnabledStandardIdentifiers": arns,
                "SecurityControlsConfiguration": {"DisabledSecurityControlIdentifiers": []},
            }
        }

    def _find_policy_id(self) -> str | None:
        """Right after the switch to central configuration, Security Hub may still refuse policy calls for a while."""
        waited = 0.0
        while True:
            try:
                with retrying():
                    for page in self.sh.get_paginator("list_configuration_policies").paginate():
                        for summary in page.get("ConfigurationPolicySummaries", []):
                            if summary.get("Name") == self.policy_name:
                                return str(summary["Id"])
                return None
            except ClientError as e:
                if "Central Configuration enabled" not in str(e) or waited >= self._timeout:
                    raise
            if not waited:
                retry_notice(
                    "Reading Security Hub configuration policies",
                    "central configuration is still starting",
                    10.0,
                )
            self._sleep(10.0)
            waited += 10.0

    @staticmethod
    def _comparable(policy: dict[str, Any]) -> tuple[bool, list[str], Any]:
        sh = policy.get("SecurityHub", {})
        return (
            bool(sh.get("ServiceEnabled")),
            sorted(sh.get("EnabledStandardIdentifiers", [])),
            sh.get("SecurityControlsConfiguration"),
        )

    def _ensure_policy(self) -> str:
        desired = self._desired_policy()
        policy_id = self._find_policy_id()
        if policy_id is None:
            resp = self.sh.create_configuration_policy(
                Name=self.policy_name,
                Description="Security Hub baseline managed by tarmac",
                ConfigurationPolicy=desired,
            )
            policy_id = str(resp["Id"])
            audit(
                "create",
                f"securityhub-policy:{self.policy_name}",
                Outcome.SUCCEEDED,
                f"Created Security Hub configuration policy '{self.policy_name}' with standards "
                f"{desired['SecurityHub']['EnabledStandardIdentifiers']}",
                policy_id=policy_id,
            )
            return policy_id

        current = self.sh.get_configuration_policy(Identifier=policy_id).get("ConfigurationPolicy", {})
        if self._comparable(current) == self._comparable(desired):
            audit(
                "create",
                f"securityhub-policy:{self.policy_name}",
                Outcome.UNCHANGED,
                f"Security Hub configuration policy '{self.policy_name}' is up to date",
                policy_id=policy_id,
            )
            return policy_id
        self.sh.update_configuration_policy(
            Identifier=policy_id,
            ConfigurationPolicy=desired,
            UpdatedReason="Synced from tarmac configuration",
        )
        audit(
            "update",
            f"securityhub-policy:{self.policy_name}",
            Outcome.SUCCEEDED,
            f"Updated Security Hub configuration policy '{self.policy_name}' to standards "
            f"{desired['SecurityHub']['EnabledStandardIdentifiers']}",
            policy_id=policy_id,
        )
        return policy_id

    def _current_association(self) -> dict[str, Any]:
        try:
            resp = self.sh.get_configuration_policy_association(Target={"RootId": self.root_id})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return {}
            raise
        return resp if isinstance(resp, dict) else {}

    def _ensure_association(self, policy_id: str) -> None:
        current = self._current_association()
        existing = str(current.get("ConfigurationPolicyId") or "")
        if existing not in ("", SELF_MANAGED, policy_id) and not adopt_existing():
            raise GovernanceError(
                f"The organization root already uses Security Hub configuration policy '{existing}', "
                "which tarmac did not create.",
                details=(
                    f"Applying '{self.policy_name}' to the root would replace it for every account that inherits it. "
                    f"{ADOPT_HINT}"
                ),
            )
        if existing == policy_id and current.get("AssociationStatus") != "FAILED":
            audit(
                "associate",
                f"securityhub-policy:{self.policy_name}",
                Outcome.UNCHANGED,
                f"Security Hub policy '{self.policy_name}' is already applied to the organization root",
                policy_id=policy_id,
            )
            return
        resp = self.sh.start_configuration_policy_association(
            ConfigurationPolicyIdentifier=policy_id, Target={"RootId": self.root_id}
        )
        if resp.get("AssociationStatus") == "FAILED":
            raise GovernanceError(
                "Security Hub could not apply the configuration policy to the organization.",
                details=str(resp.get("AssociationStatusMessage", "")),
            )
        audit(
            "associate",
            f"securityhub-policy:{self.policy_name}",
            Outcome.SUCCEEDED,
            f"Applied Security Hub policy '{self.policy_name}' to the organization root "
            f"(status {resp.get('AssociationStatus', 'PENDING')})",
            policy_id=policy_id,
        )
