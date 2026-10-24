"""The dry-run plan: what each deployment phase would change, worked out with read-only AWS calls.

Every item names one thing a phase manages and the action a live run would take on it. Stacks are compared on
their exact template text, the parameters tarmac passes and their tags, so NO CHANGE means the live run leaves
them alone. A read that fails marks its item UNKNOWN instead of stopping the plan.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ..core import inventory
from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, normalize_account_name
from ..core.config_schema import AccountDef, BaselineStackDef, GroupDef, OUDef, ServiceControlPoliciesConfig
from ..core.exceptions import AWS_ERRORS, aws_error_code
from ..core.models import TAG_MANAGED_BY, AccountPlanItem, TeardownItemReport
from ..core.org_accounts import get_active_account_id_map
from ..core.stack_names import Stack
from ..core.tagging import merge_tags
from ..core.templates import resolve_resource_path
from ..core.text import plural
from .accounts import AccountService
from .baseline import BUDGET_TEMPLATE, budget_parameters, budget_stack_name
from .baseline_stacks import BaselineStacksService, stack_set_name
from .cloudformation import CloudFormationService, lock_table_wanted
from .config_recorder import service_linked_role_arn
from .guardduty_export import FindingsExport, findings_export, reconcile_findings_export
from .identity import IdentityService
from .log_encryption import resolve_log_encryption
from .organization import DEFAULT_TRUSTED_SERVICES, OrganizationService, contact_types
from .ou import OUService
from .scp import SCPService
from .security_off import SECURITY_HUB_WARNING, SecurityServicesOff
from .settings_off import ROOT_SESSIONS_WARNING, settings_off, turns_off_root_sessions
from .stack_parameters import (
    audit_hardening_parameters,
    backend_parameters,
    cloudtrail_parameters,
    config_recorder_advice,
    config_recorder_parameters,
    config_recorder_regions,
    log_archive_parameters,
    object_lock_advice,
    root_alert_parameters,
    root_alert_regions,
)
from .stackset import StackSetService
from .teardown import TeardownService

PHASE_TITLES = {
    1: "Organization",
    2: "Organizational units and SCPs",
    3: "Log archive and CloudTrail",
    4: "Accounts",
    5: "Backend, hardening and security services",
    6: "IAM Identity Center",
}
UNKNOWN = "UNKNOWN"
NO_CHANGE = "NO CHANGE"
_ACCOUNT_ACTIONS = {
    "CREATE": "CREATE",
    "MOVE": "MOVE",
    "NOOP": NO_CHANGE,
    "SUSPEND": "SUSPEND",
    "SUSPENDED": "SKIP",
}


@dataclass
class PlanItem:
    kind: str
    name: str
    action: str
    detail: str = ""
    account: str = ""


@dataclass
class PhasePlan:
    phase: int
    title: str
    items: list[PlanItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DeploymentPlan:
    region: str
    phases: list[PhasePlan] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return dict(Counter(item.action for phase in self.phases for item in phase.items))

    def to_dict(self) -> dict[str, Any]:
        return {"dry_run": True, **asdict(self), "summary": self.counts()}


def _ou_names(ous: list[OUDef], parent: str = "Root") -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = []
    for ou in ous:
        names.append((ou.name, parent))
        names.extend(_ou_names(ou.children, ou.name))
    return names


class Planner:
    """Builds the plan for the requested phases. Never changes anything in AWS."""

    def __init__(
        self,
        session_mgr: AwsSessionManager,
        bundle: ConfigBundle,
        region: str,
        project_root: Path,
        custom_tags: dict[str, str] | None = None,
        identity_region: str | None = None,
        only_accounts: list[str] | None = None,
    ) -> None:
        self.session_mgr = session_mgr
        self.bundle = bundle
        self.region = region
        self.project_root = project_root
        self.custom_tags = custom_tags or {}
        self.identity_region = identity_region or bundle.identity.identity_center.region or region
        self.only_accounts = {normalize_account_name(n) for n in only_accounts or []}
        self.org_name = bundle.org.organization.name
        self.org_tags = bundle.get_organization_tags()
        self.cfn = CloudFormationService(session_mgr)

    def build(self, phases: list[int]) -> DeploymentPlan:
        builders: dict[int, Callable[[PhasePlan], None]] = {
            1: self._phase_1,
            2: self._phase_2,
            3: self._phase_3,
            4: self._phase_4,
            5: lambda p: self._phase_5(p, include_log_archive=3 not in phases),
            6: self._phase_6,
        }
        plan = DeploymentPlan(region=self.region)
        for number in phases:
            phase = PhasePlan(number, PHASE_TITLES[number])
            try:
                builders[number](phase)
            except AWS_ERRORS as e:
                phase.items.append(
                    PlanItem("phase", str(number), UNKNOWN, f"could not read the current state: {e}")
                )
            for item in phase.items:
                audit(
                    "plan",
                    f"{item.kind}:{item.name}",
                    Outcome.SIMULATED,
                    f"[DRY-RUN] {item.kind} '{item.name}' would be {item.action}"
                    + (f": {item.detail}" if item.detail else ""),
                    dry_run=True,
                    phase=number,
                    planned_action=item.action,
                )
            plan.phases.append(phase)
        return plan

    def _check(
        self, phase: PhasePlan, kind: str, name: str, check: Callable[[], tuple[str, str]], account: str = ""
    ) -> None:
        """Add one item; a failed read is shown as UNKNOWN instead of stopping the plan."""
        try:
            action, detail = check()
        except AWS_ERRORS as e:
            action, detail = UNKNOWN, f"could not read the current state: {e}"
        phase.items.append(PlanItem(kind, name, action, detail, account))

    def _stack(
        self,
        phase: PhasePlan,
        cfn_client: Any,
        stack_name: str,
        account: str,
        parameters: dict[str, str],
        template: str,
        account_tags: dict[str, str] | None = None,
    ) -> None:
        self._check(
            phase,
            "stack",
            stack_name,
            lambda: self.cfn.preview_stack(
                cfn_client,
                stack_name,
                template_file=resolve_resource_path(template, project_root=self.project_root),
                parameters=parameters,
                tags=self.custom_tags,
                org_tags=self.org_tags,
                account_tags=account_tags,
            ),
            account,
        )

    def _adoptions(
        self, cfn_client: Any, stack_name: str, action: str, existing: set[str], logical_ids: dict[str, str]
    ) -> str:
        """Declared names that exist in AWS but not in the stack, which a deploy imports first ("" if none)."""
        if not existing:
            return ""
        in_stack = set() if action in ("CREATE", "REPLACE") else self.cfn.resource_ids(cfn_client, stack_name)
        return ", ".join(sorted(name for name in existing if logical_ids.get(name) not in in_stack))

    @cached_property
    def management_id(self) -> str:
        return str(self.session_mgr.get_caller_identity().get("Account", ""))

    @cached_property
    def org_id(self) -> str:
        """The organization ID, or "" when there is no organization yet. Other errors propagate."""
        try:
            return str(
                self.session_mgr.get_client("organizations").describe_organization()["Organization"]["Id"]
            )
        except ClientError as e:
            if aws_error_code(e) != "AWSOrganizationsNotInUseException":
                raise
            return ""

    @cached_property
    def accounts(self) -> dict[str, str]:
        return get_active_account_id_map(self.session_mgr) if self.org_id else {}

    @cached_property
    def root_id(self) -> str:
        return OUService(self.session_mgr).get_root_id() if self.org_id else ""

    @cached_property
    def recorded(self) -> inventory.Inventory:
        """What tarmac recorded creating, read without writing it back."""
        return inventory.read(self.session_mgr, self.org_name, self.bundle.org.organization.primary_region)

    @cached_property
    def ou_map(self) -> dict[str, str]:
        return OUService(self.session_mgr).list_all_ous() if self.org_id else {}

    def _member_cfn(self, account_id: str, region: str | None = None) -> Any:
        return self.session_mgr.get_member_client(
            account_id, "cloudformation", region_name=region or self.region
        )

    def _account_id(self, name: str | None) -> str:
        return self.bundle.resolve_account_id(name, self.accounts) or ""

    def _missing_account(self, phase: PhasePlan, name: str, *stacks: str) -> None:
        for stack in stacks:
            phase.items.append(PlanItem("stack", stack, "CREATE", f"once account '{name}' exists", name))

    # Phase 1

    def _phase_1(self, phase: PhasePlan) -> None:
        org = OrganizationService(self.session_mgr)
        self._stack(
            phase,
            self.session_mgr.get_client(
                "cloudformation", region_name=self.bundle.org.organization.primary_region
            ),
            Stack.INVENTORY.for_org(self.org_name),
            "management",
            {},
            template="cloudformation/tarmac-inventory.yaml",
        )
        phase.items.append(
            PlanItem("organization", self.org_name, NO_CHANGE, self.org_id)
            if self.org_id
            else PlanItem("organization", self.org_name, "CREATE", "with all features")
        )
        contacts = self.bundle.org.contacts
        stale = org.stale_contacts(contacts)
        for label, contact in contact_types(contacts).items():
            phase.items.append(
                PlanItem(
                    "alternate contact", label.lower(), "UPDATE", f"set to {contact.name} <{contact.email}>"
                )
                if label in stale
                else PlanItem("alternate contact", label.lower(), NO_CHANGE, str(contact.email))
            )
        self._check(phase, "trusted access", "AWS services", lambda: self._trusted_access(org))
        root = self.bundle.org.root_access_management
        if root.enabled:
            self._check(phase, "root access", "centralized root access", lambda: self._root_features(org))
            if root.delegated_admin_account:
                self._check(
                    phase,
                    "delegated admin",
                    f"IAM: {root.delegated_admin_account}",
                    lambda: self._delegated(org, "iam.amazonaws.com", root.delegated_admin_account or ""),
                )
        cost_tags = self.bundle.get_cost_allocation_tags()
        if cost_tags:
            self._check(
                phase, "cost allocation tags", ", ".join(cost_tags), lambda: self._cost_tags(org, cost_tags)
            )
        if self.org_id:
            if turns_off_root_sessions(self.bundle, self.recorded):
                phase.notes.append(ROOT_SESSIONS_WARNING)
            self._removals(
                phase,
                "turned off in the config",
                lambda t: t.teardown_org_settings(
                    self.recorded, dry_run=True, only=settings_off(self.bundle)
                ),
            )
        if self.bundle.org.organization.delete_default_vpc:
            phase.items.append(
                PlanItem(
                    "default VPCs", "management account", "APPLY", "deletes any default VPC in every Region"
                )
            )

    def _trusted_access(self, org: OrganizationService) -> tuple[str, str]:
        missing = (
            org.missing_trusted_services(DEFAULT_TRUSTED_SERVICES)
            if self.org_id
            else DEFAULT_TRUSTED_SERVICES
        )
        return ("APPLY", "enable " + ", ".join(missing)) if missing else (NO_CHANGE, "")

    def _root_features(self, org: OrganizationService) -> tuple[str, str]:
        root = self.bundle.org.root_access_management
        wanted = {
            "RootCredentialsManagement": root.enable_root_credentials_management,
            "RootSessions": root.enable_root_sessions,
        }
        enabled = org._enabled_root_features()
        missing = [name for name, on in wanted.items() if on and name not in enabled]
        if not self.org_id or org.missing_trusted_services(["iam.amazonaws.com"]):
            missing.insert(0, "IAM trusted access")
        return ("APPLY", "enable " + ", ".join(missing)) if missing else (NO_CHANGE, "")

    def _delegated(self, org: OrganizationService, principal: str, account_name: str) -> tuple[str, str]:
        account_id = self._account_id(account_name)
        if not account_id:
            return "APPLY", f"once account '{account_name}' exists"
        if account_id in org.delegated_administrator_ids(principal):
            return NO_CHANGE, account_id
        return "APPLY", f"register {account_id}"

    def _cost_tags(self, org: OrganizationService, keys: list[str]) -> tuple[str, str]:
        inactive = org.inactive_cost_allocation_tags(keys)
        return ("APPLY", "activate " + ", ".join(inactive)) if inactive else (NO_CHANGE, "")

    # Phase 2

    def _phase_2(self, phase: PhasePlan) -> None:
        for name, parent in _ou_names(self.bundle.org.ou_structure):
            self._check(
                phase,
                "OU",
                name,
                lambda name=name, parent=parent: (
                    (NO_CHANGE, "") if name in self.ou_map else ("CREATE", f"under {parent}")
                ),
            )
        scps = self.bundle.org.service_control_policies
        if scps and scps.enabled and scps.policies:
            self._check(
                phase, "stack", Stack.ORGANIZATION_SCPS.for_org(self.org_name), lambda: self._scp_stack(scps)
            )
        elif self.org_id:
            self._removals(
                phase,
                "SCPs are off or none are declared",
                lambda t: t.teardown_scps(self.bundle, dry_run=True),
            )

    def _removals(
        self,
        phase: PhasePlan,
        why: str,
        teardown: Callable[[TeardownService], list[TeardownItemReport]],
        action: str = "DELETE",
    ) -> None:
        """What a deploy removes because the config turns it off: the teardown of it, simulated."""
        try:
            items = teardown(TeardownService(self.session_mgr))
        except AWS_ERRORS as e:
            phase.items.append(PlanItem("removal", why, UNKNOWN, f"could not read the current state: {e}"))
            return
        for item in items:
            if item.action == "SIMULATED":
                phase.items.append(
                    PlanItem(item.resource_type, item.resource_name, action, why, item.account_name)
                )
            elif item.action == "FAILED":
                phase.items.append(
                    PlanItem(item.resource_type, item.resource_name, UNKNOWN, item.message, item.account_name)
                )

    def _scp_stack(self, scps: ServiceControlPoliciesConfig) -> tuple[str, str]:
        names = ", ".join(p.name for p in scps.policies)
        if not self.org_id:
            return "CREATE", names
        service = SCPService(self.session_mgr)
        stack_name = Stack.ORGANIZATION_SCPS.for_org(self.org_name)
        body = yaml.dump(
            service.synthesize_template(scps, self.root_id, self.ou_map, self.project_root), sort_keys=False
        )
        cfn_client = self.session_mgr.get_client("cloudformation")
        action, detail = self.cfn.preview_stack(
            cfn_client,
            stack_name,
            template_body=body,
            parameters={},
            tags=self.custom_tags,
            org_tags=self.org_tags,
        )
        adopted = self._adoptions(
            cfn_client,
            stack_name,
            action,
            {p.name for p in scps.policies} & set(service.list_existing_scps()),
            service._logical_ids_for_policies(scps.policies),
        )
        if adopted:
            action, detail = "IMPORT", "; ".join(filter(None, ["adopts existing " + adopted, detail]))
        new_ous = sorted({t for p in scps.policies for t in p.targets} - set(self.ou_map) - {"Root", "root"})
        if new_ous:
            detail = "; ".join(filter(None, [detail, f"targets {', '.join(new_ous)} once created"]))
        return action, detail or names

    # Phase 3

    def _log_archive_stack(self, phase: PhasePlan) -> None:
        name = self.bundle.get_log_archive_account_name() or "log-archive"
        stack_name = Stack.LOG_ARCHIVE.for_org(self.org_name)
        advice = object_lock_advice(self.bundle)
        if advice:
            phase.notes.append(advice)
        account_id = self._account_id(name)
        if not account_id:
            self._missing_account(phase, name, stack_name)
            return
        resolve_log_encryption(self.session_mgr, self.bundle, self.region, account_id)
        self._stack(
            phase,
            self._member_cfn(account_id),
            stack_name,
            name,
            log_archive_parameters(
                self.bundle,
                self.org_id,
                self.management_id,
                self._account_id(self.bundle.get_audit_account_name() or "audit"),
            ),
            template="cloudformation/log-archive-hardening.yaml",
            account_tags=self.bundle.get_account_tags(name),
        )

    def _phase_3(self, phase: PhasePlan) -> None:
        name = self.bundle.get_log_archive_account_name() or "log-archive"
        trail_stack = Stack.CLOUDTRAIL.for_org(self.org_name)
        account_id = self._account_id(name)
        if not account_id:
            declared = self.bundle.get_account(name)
            phase.items.append(
                PlanItem(
                    "account",
                    name,
                    "CREATE",
                    f"in OU {declared.ou}" if declared else "not declared in accounts.yaml",
                )
            )
        self._log_archive_stack(phase)
        if not account_id:
            self._missing_account(phase, name, trail_stack)
            return
        self._stack(
            phase,
            self.session_mgr.get_client("cloudformation", region_name=self.region),
            trail_stack,
            "management",
            cloudtrail_parameters(
                self.bundle,
                account_id,
                self.cfn._fetch_stack_outputs(
                    self._member_cfn(account_id), Stack.LOG_ARCHIVE.for_org(self.org_name)
                ).get("CloudTrailBucketName", ""),
                bool(self.bundle.org.cloudtrail.enable_kms),
            ),
            template="cloudformation/organization-cloudtrail.yaml",
        )

    # Phase 4

    def _baseline_stacks(self, phase: PhasePlan) -> None:
        stacks = self.bundle.org.baseline_stacks
        for stack in stacks:
            name = stack_set_name(self.org_name, stack.name)
            self._check(
                phase,
                "stack set",
                name,
                lambda name=name, stack=stack: self._baseline_stack(name, stack),
                ", ".join(stack.target_ous),
            )
        if not self.org_id:
            return
        try:
            undeclared = BaselineStacksService(self.session_mgr, self.region).undeclared(
                self.org_name, stacks
            )
        except AWS_ERRORS as e:
            phase.items.append(
                PlanItem("stack sets", "baseline stacks", UNKNOWN, f"could not read the current state: {e}")
            )
            return
        for name in undeclared:
            phase.items.append(PlanItem("stack set", name, "DELETE", "no longer in baseline_stacks"))

    def _baseline_stack(self, name: str, stack: BaselineStackDef) -> tuple[str, str]:
        """The StackSet's own change, plus the OUs and Regions whose stack instances would be added or removed."""
        action, detail = self._stack_set(name, stack.template_file, stack.parameters)
        if action not in (NO_CHANGE, "UPDATE"):
            return action, detail or f"in {', '.join(stack.regions)}"
        targets = {
            t: self.root_id if t.lower() == "root" else self.ou_map.get(t, "") for t in stack.target_ous
        }
        present: dict[str, set[str]] = {}
        cf = self.session_mgr.get_client("cloudformation", region_name=self.region)
        for instance in StackSetService().list_instances(cf, name):
            present.setdefault(str(instance["OrganizationalUnitId"]), set()).add(str(instance["Region"]))
        names = {ou_id: ou for ou, ou_id in self.ou_map.items()} | {self.root_id: "root"}
        changes = ["template, parameters or tags"] if action == "UPDATE" else []
        changes += [f"remove {names.get(ou, ou)}" for ou in sorted(set(present) - set(targets.values()))]
        for target, ou_id in targets.items():
            have = present.get(ou_id, set())
            # An OU without accounts has no stack instances, and deploying to it changes nothing.
            if not have and not self._has_accounts(target):
                continue
            if add := [r for r in stack.regions if r not in have]:
                changes.append(f"add {', '.join(add)} in {target}")
            if drop := sorted(have - set(stack.regions)):
                changes.append(f"remove {', '.join(drop)} in {target}")
        return ("UPDATE", "; ".join(changes)) if changes else (NO_CHANGE, f"in {', '.join(stack.regions)}")

    def _has_accounts(self, target: str) -> bool:
        """Whether a declared account sits in the OU, or in an OU below it (``root``: in any OU)."""
        homes = {a.ou for a in self.bundle.accounts.accounts}
        if target.lower() == "root":
            return bool(homes)

        def find(ous: list[OUDef]) -> OUDef | None:
            for ou in ous:
                if ou.name == target:
                    return ou
                if (found := find(ou.children)) is not None:
                    return found
            return None

        ou = find(self.bundle.org.ou_structure)
        return ou is not None and bool(homes & ({ou.name} | ConfigBundle._collect_ou_names(ou.children)))

    def _account_removals(
        self, phase: PhasePlan, declared: list[AccountDef], planned: dict[str, AccountPlanItem]
    ) -> None:
        """Budgets and cost anomaly monitors of accounts whose config no longer declares them."""
        live = {
            a.name: str(planned[a.name].account_id)
            for a in declared
            if a.name in planned and planned[a.name].account_id and planned[a.name].action != "SUSPENDED"
        }
        for acct in (a for a in declared if a.name in live and a.baseline.budget is None):
            self._removals(
                phase,
                "no budget declared",
                lambda t, a=acct.name: t.teardown_account_budget(a, live[a], dry_run=True),
            )
        anomaly_off = {
            a.name: live[a.name]
            for a in declared
            if a.name in live
            and (a.baseline.anomaly_detection is None or not a.baseline.anomaly_detection.enabled)
        }
        if anomaly_off:
            self._removals(
                phase,
                "anomaly_detection is off",
                lambda t: t.teardown_anomaly_monitors(anomaly_off, dry_run=True),
            )

    def _phase_4(self, phase: PhasePlan) -> None:
        declared = [
            a
            for a in self.bundle.accounts.accounts
            if not self.only_accounts or normalize_account_name(a.name) in self.only_accounts
        ]
        missing_ous = sorted({a.ou for a in declared} - set(self.ou_map))
        if missing_ous:
            phase.notes.append(
                f"{plural(len(missing_ous), 'OU')} not created yet ({', '.join(missing_ous)}). Phase 2 creates OUs, "
                "and phase 4 stops until then."
            )
        service = AccountService(self.session_mgr)
        items = service.plan(self.bundle.accounts, self.ou_map) if self.org_id else []
        planned = {item.name: item for item in items}
        org_tags = self.bundle.get_organization_tags()
        for acct in declared:
            current = planned.get(acct.name)
            if current is None:
                phase.items.append(PlanItem("account", acct.name, "CREATE", f"in OU {acct.ou}", acct.name))
            else:
                action, detail = _ACCOUNT_ACTIONS.get(current.action, current.action), current.reason
                if action == NO_CHANGE and current.account_id:
                    live = service.get_account_tags(current.account_id)
                    stale = sorted(k for k, v in {**org_tags, **acct.tags}.items() if live.get(k) != str(v))
                    if stale:
                        action, detail = "UPDATE", "tags " + ", ".join(stale)
                phase.items.append(PlanItem("account", acct.name, action, detail, acct.name))
                if current.account_id and current.action != "SUSPENDED":
                    self._check(
                        phase,
                        "alternate contacts",
                        "billing, operations, security",
                        lambda a=current.account_id: self._member_contacts(a),
                        acct.name,
                    )
            budget = acct.baseline.budget if acct.baseline else None
            if not budget or (current is not None and current.action == "SUSPENDED"):
                continue
            stack_name = budget_stack_name(acct.name)
            if current is None or not current.account_id:
                self._missing_account(phase, acct.name, stack_name)
                continue
            self._stack(
                phase,
                self._member_cfn(current.account_id, self.session_mgr.default_region),
                stack_name,
                acct.name,
                budget_parameters(acct.name, budget),
                template=BUDGET_TEMPLATE,
                account_tags=acct.tags,
            )
        self._account_removals(phase, declared, planned)
        if self.only_accounts:
            phase.notes.append(
                "--account is set, so accounts missing from accounts.yaml are not quarantined."
            )
        else:
            for item in items:
                if item.action == "SUSPEND":
                    phase.items.append(PlanItem("account", item.name, "SUSPEND", item.reason, item.name))
            self._baseline_stacks(phase)
        phase.notes.append("Account IDs are written to outputs/accounts.json and outputs/accounts.env.")

    def _member_contacts(self, account_id: str) -> tuple[str, str]:
        stale = OrganizationService(self.session_mgr).stale_contacts(self.bundle.org.contacts, account_id)
        return ("UPDATE", "set " + ", ".join(t.lower() for t in stale)) if stale else (NO_CHANGE, "")

    # Phase 5

    def _phase_5(self, phase: PhasePlan, include_log_archive: bool) -> None:
        org = OrganizationService(self.session_mgr)
        backend_name = self.bundle.get_backend_account_name() or "deployment"
        backend_stack = Stack.TERRAFORM_BACKEND.for_org(self.org_name)
        backend_id = self._account_id(backend_name)
        if backend_id:
            cfn = self._member_cfn(backend_id)
            enable_dynamodb, warning = lock_table_wanted(
                cfn, backend_stack, self.bundle.org.terraform_backend.enable_dynamodb
            )
            if warning:
                phase.notes.append(warning)
            self._stack(
                phase,
                cfn,
                backend_stack,
                backend_name,
                backend_parameters(self.bundle, enable_dynamodb),
                template="cloudformation/terraform-backend.yaml",
                account_tags=self.bundle.get_account_tags(backend_name),
            )
        else:
            self._missing_account(phase, backend_name, backend_stack)

        if include_log_archive:
            self._log_archive_stack(phase)

        audit_name = self.bundle.get_audit_account_name() or "audit"
        audit_stack = Stack.AUDIT_ACCOUNT.for_org(self.org_name)
        audit_id = self._account_id(audit_name)
        if audit_id:
            for principal in ("config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"):
                self._check(
                    phase,
                    "delegated admin",
                    f"{principal.split('.')[0]}: {audit_name}",
                    lambda principal=principal: self._delegated(org, principal, audit_name),
                )
            self._stack(
                phase,
                self._member_cfn(audit_id),
                audit_stack,
                audit_name,
                audit_hardening_parameters(self.bundle, self.org_id),
                template="cloudformation/audit-account-hardening.yaml",
                account_tags=self.bundle.get_account_tags(audit_name),
            )
        else:
            self._missing_account(phase, audit_name, audit_stack)

        self._config_recorder(phase)
        self._root_alert(phase)

        security = self.bundle.org.security_services
        for label, principal, enabled in (
            ("GuardDuty", "guardduty.amazonaws.com", security.guardduty.enabled),
            ("Security Hub", "securityhub.amazonaws.com", security.securityhub.enabled),
        ):
            if enabled:
                self._check(
                    phase,
                    "security service",
                    label,
                    lambda principal=principal: self._security_service(org, principal, audit_name),
                    audit_name,
                )
        audit_id = self._account_id(audit_name)
        if audit_id and not (security.guardduty.enabled and security.securityhub.enabled):
            self._security_off(phase, audit_id)
        if security.guardduty.enabled and audit_id:
            self._findings_export(phase, audit_id, audit_name)

    def _security_off(self, phase: PhasePlan, audit_id: str) -> None:
        """GuardDuty and Security Hub that tarmac runs but the config turns off."""
        security = self.bundle.org.security_services
        regions = [self.region, *self.bundle.org.organization.additional_regions]
        off = SecurityServicesOff(self.session_mgr)
        if not security.guardduty.enabled:
            self._removals(
                phase,
                "guardduty is off; findings are kept",
                lambda _t: off.suspend_guardduty(audit_id, regions, dry_run=True),
                action="SUSPEND",
            )
        if not security.securityhub.enabled:
            mgmt_id = str(self.session_mgr.get_caller_identity().get("Account", ""))
            before = len(phase.items)
            self._removals(
                phase,
                "securityhub is off",
                lambda _t: off.disable_securityhub(
                    self.bundle, audit_id, regions, self.accounts, mgmt_id, dry_run=True
                ),
            )
            if len(phase.items) > before:
                phase.notes.append(SECURITY_HUB_WARNING)

    def _findings_export(self, phase: PhasePlan, audit_id: str, audit_name: str) -> None:
        """The audit detectors' S3 export of GuardDuty findings, per Region."""
        export = findings_export(self.session_mgr, self.bundle, self.region, self.accounts)
        for region in config_recorder_regions(self.bundle, self.region):
            name = f"GuardDuty findings ({region})"
            if export is None:
                phase.items.append(
                    PlanItem(
                        "findings export", name, "CREATE", "once the log archive has its findings bucket"
                    )
                )
                continue

            def check(region: str = region, export: FindingsExport = export) -> tuple[str, str]:
                gd = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=region)
                detectors = gd.list_detectors().get("DetectorIds", [])
                if not detectors:
                    return ("CREATE", "with the detector") if export.bucket_arn else (NO_CHANGE, "")
                action = reconcile_findings_export(gd, str(detectors[0]), export, region, dry_run=True)
                detail = "export stops; exported findings stay" if action == "DELETE" else ""
                return action, detail or export.bucket_arn.rsplit(":", 1)[-1]

            self._check(phase, "findings export", name, check, audit_name)

    def _security_service(self, org: OrganizationService, principal: str, audit_name: str) -> tuple[str, str]:
        action, detail = self._delegated(org, principal, audit_name)
        regions = ", ".join(config_recorder_regions(self.bundle, self.region))
        if action == NO_CHANGE:
            return "APPLY", f"delegated to {detail}; settings reconciled in {regions}"
        return action, f"{detail}; enable in {regions}"

    def _config_recorder(self, phase: PhasePlan) -> None:
        advice = config_recorder_advice(self.bundle)
        if advice:
            phase.notes.append(advice)
        if not self.bundle.org.security_services.config_recorder.enabled:
            if self.org_id:
                self._removals(
                    phase,
                    "config_recorder is off",
                    lambda t: t.teardown_config_recorder(self.bundle, self.region, dry_run=True),
                )
            return
        name = Stack.CONFIG_RECORDER.for_org(self.org_name)
        regions = config_recorder_regions(self.bundle, self.region)
        log_archive_name = self.bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = self._account_id(log_archive_name)
        outputs = (
            self.cfn._fetch_stack_outputs(
                self._member_cfn(log_archive_id), Stack.LOG_ARCHIVE.for_org(self.org_name)
            )
            if log_archive_id
            else {}
        )
        bucket = outputs.get("ConfigBucketName", "")
        if not bucket:
            phase.items.append(
                PlanItem("stack set", name, "CREATE", "once the log archive has its Config bucket")
            )
            for region in regions:
                phase.items.append(PlanItem("stack", f"{name} ({region})", "CREATE", "", "management"))
            return
        parameters = config_recorder_parameters(
            self.bundle, self.region, bucket, outputs.get("KmsKeyArn", "")
        )
        self._check(
            phase,
            "stack set",
            name,
            lambda: self._stack_set(name, "cloudformation/config-recorder.yaml", parameters),
            "all member accounts",
        )
        management_parameters = {
            **parameters,
            "RecorderRoleArn": service_linked_role_arn(self.session_mgr, self.management_id),
        }
        for region in regions:
            self._check(
                phase,
                "stack",
                f"{name} ({region})",
                lambda region=region: self.cfn.preview_stack(
                    self._member_cfn(self.management_id, region),
                    name,
                    template_file=resolve_resource_path(
                        "cloudformation/config-recorder.yaml", project_root=self.project_root
                    ),
                    parameters=management_parameters,
                    tags=self.custom_tags,
                    org_tags=self.org_tags,
                ),
                "management",
            )

    def _stack_set(self, name: str, template: str, parameters: dict[str, str]) -> tuple[str, str]:
        stack_sets = StackSetService()
        existing = stack_sets.describe(
            self.session_mgr.get_client("cloudformation", region_name=self.region), name
        )
        if existing is None:
            return "CREATE", ""
        if not stack_sets.owned(existing):
            return "BLOCKED", f"exists without the {TAG_MANAGED_BY}=tarmac tag; tarmac will not update it"
        body = resolve_resource_path(template, project_root=self.project_root).read_text(encoding="utf-8")
        cfn_parameters = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
        tags = merge_tags(self.org_tags, self.custom_tags, {TAG_MANAGED_BY: "tarmac"})
        if stack_sets.unchanged(existing, body, cfn_parameters, tags):
            return NO_CHANGE, "stack instances are reconciled on apply"
        return "UPDATE", ""

    def _root_alert(self, phase: PhasePlan) -> None:
        if not self.bundle.org.security_services.root_alert.enabled:
            if self.org_id:
                self._removals(
                    phase,
                    "root_alert is off",
                    lambda t: t.teardown_root_alert(self.bundle, self.region, dry_run=True),
                )
            return
        name = Stack.ROOT_ALERT.for_org(self.org_name)
        parameters = root_alert_parameters(self.bundle)
        if parameters is None:
            phase.items.append(
                PlanItem("stack", name, "SKIP", "nobody is set to receive the alert", "management")
            )
            return
        for region in root_alert_regions(self.bundle, self.region):
            self._check(
                phase,
                "stack",
                f"{name} ({region})",
                lambda region=region: self.cfn.preview_stack(
                    self.session_mgr.get_client("cloudformation", region_name=region),
                    name,
                    template_file=resolve_resource_path(
                        "cloudformation/management-root-alert.yaml", project_root=self.project_root
                    ),
                    parameters=parameters,
                    tags=self.custom_tags,
                    org_tags=self.org_tags,
                ),
                "management",
            )

    # Phase 6

    def _phase_6(self, phase: PhasePlan) -> None:
        cfg = self.bundle.identity.identity_center
        phase.notes.append(f"Identity Center Region: {self.identity_region}")
        session = (
            self.session_mgr
            if self.session_mgr.default_region == self.identity_region
            else AwsSessionManager(region_name=self.identity_region)
        )
        identity = IdentityService(session, preferred_region=self.identity_region)
        try:
            instance_arn, _ = identity.get_instance_details()
        except AWS_ERRORS as e:
            phase.items.append(PlanItem("identity center", "instance", UNKNOWN, f"not readable: {e}"))
            return
        if cfg.permission_sets:
            self._check(
                phase,
                "stack",
                Stack.PERMISSION_SETS.for_org(self.org_name),
                lambda: self._permission_sets(identity, session, instance_arn),
            )
        users: dict[str, str | None] = {}
        for user in [cfg.admin_user, cfg.breakglass_user, *cfg.additional_users]:
            users[user.username] = identity.get_user_id_by_username(user.username)
            phase.items.append(
                PlanItem(
                    "user", user.username, NO_CHANGE if users[user.username] else "CREATE", str(user.email)
                )
            )
        permission_sets = identity.list_permission_sets(instance_arn)
        owned = set(self.recorded.get("identity-group"))
        adopted: list[str] = []
        for group in cfg.groups:
            try:
                group_id = identity.get_group_id_by_name(group.name)
                phase.items.append(PlanItem("group", group.name, NO_CHANGE if group_id else "CREATE"))
            except AWS_ERRORS as e:
                group_id = None
                phase.items.append(
                    PlanItem("group", group.name, UNKNOWN, f"could not read the current state: {e}")
                )
            for assignment in group.assignments:
                self._check(
                    phase,
                    "assignment",
                    f"{group.name} -> {assignment.permission_set}",
                    lambda a=assignment, gid=group_id: self._assignment(
                        identity, instance_arn, gid, permission_sets.get(a.permission_set), a.accounts
                    ),
                )
            for member in group.members:
                uid = users.get(member) or identity.get_user_id_by_username(member)
                self._check(
                    phase,
                    "membership",
                    f"{member} in {group.name}",
                    lambda gid=group_id, uid=uid: (
                        (NO_CHANGE, "")
                        if gid and uid and identity.is_group_member(gid, uid)
                        else ("CREATE", "")
                    ),
                )
            if group_id and group.name in owned:
                self._undeclared_access(phase, identity, instance_arn, group, group_id, permission_sets)
            elif group_id:
                adopted.append(group.name)
        if adopted:
            phase.notes.append(
                f"Not created by tarmac, so only added to: {', '.join(adopted)}. Their other members and "
                "assignments stay. `tarmac import` records them so tarmac manages them fully."
            )

        self._removals(
            phase,
            "not in identity.yaml",
            lambda _t: TeardownService(session).teardown_identity_principals(
                self.identity_region, self.recorded, dry_run=True, only=settings_off(self.bundle)
            ),
        )

    def _undeclared_access(
        self,
        phase: PhasePlan,
        identity: IdentityService,
        instance_arn: str,
        group: GroupDef,
        group_id: str,
        permission_sets: dict[str, str],
    ) -> None:
        """What a deploy removes from the group because identity.yaml no longer declares it."""
        managed = {normalize_account_name(a.name) for a in self.bundle.accounts.accounts}
        managed_ids = {i for name, i in self.accounts.items() if normalize_account_name(name) in managed}
        try:
            assignments, members = identity.undeclared_access(
                instance_arn, group, group_id, permission_sets, self.accounts, managed_ids
            )
        except AWS_ERRORS as e:
            phase.items.append(PlanItem("group", group.name, UNKNOWN, f"could not read its access: {e}"))
            return
        set_names = {arn: name for name, arn in permission_sets.items()}
        account_names = {i: name for name, i in self.accounts.items()}
        for account_id, ps_arn in assignments:
            account = account_names.get(account_id, account_id)
            name = f"{group.name} -> {set_names.get(ps_arn, ps_arn)}"
            phase.items.append(PlanItem("assignment", name, "DELETE", "not in identity.yaml", account))
        for username in members:
            phase.items.append(
                PlanItem("membership", f"{username} in {group.name}", "DELETE", "not in identity.yaml")
            )

    def _permission_sets(
        self, identity: IdentityService, session: AwsSessionManager, instance_arn: str
    ) -> tuple[str, str]:
        sets = self.bundle.identity.identity_center.permission_sets
        body = yaml.dump(
            identity.synthesize_permission_sets_template(instance_arn, sets, project_root=self.project_root),
            sort_keys=False,
        )
        cfn_client = session.get_client("cloudformation", region_name=self.identity_region)
        stack_name = Stack.PERMISSION_SETS.for_org(self.org_name)
        action, detail = self.cfn.preview_stack(
            cfn_client,
            stack_name,
            template_body=body,
            parameters={},
            tags=self.custom_tags,
            org_tags=self.org_tags,
        )
        adopted = self._adoptions(
            cfn_client,
            stack_name,
            action,
            {ps.name for ps in sets} & set(identity.list_permission_sets(instance_arn)),
            identity._logical_ids_for_permission_sets(sets),
        )
        if adopted:
            return "IMPORT", "; ".join(filter(None, ["adopts existing " + adopted, detail]))
        return action, detail or ", ".join(ps.name for ps in sets)

    def _assignment(
        self,
        identity: IdentityService,
        instance_arn: str,
        group_id: str | None,
        permission_set_arn: str | None,
        targets: list[str],
    ) -> tuple[str, str]:
        account_ids = identity._resolve_target_account_ids(
            targets, self.accounts, list(self.accounts.values())
        )
        if not group_id or not permission_set_arn:
            return "CREATE", f"{plural(len(account_ids), 'account')}"
        missing = [
            account_id
            for account_id in account_ids
            if not identity._assignment_exists(instance_arn, account_id, permission_set_arn, group_id)
        ]
        if missing:
            return "CREATE", f"{len(missing)} of {plural(len(account_ids), 'account')}"
        return NO_CHANGE, f"{plural(len(account_ids), 'account')}"
