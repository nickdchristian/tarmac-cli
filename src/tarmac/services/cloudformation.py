"""CloudFormation Stack Deployment Service."""

import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import yaml
from botocore.exceptions import BotoCoreError, ClientError, WaiterError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, DeploymentError, aws_error_message
from ..core.models import StackDeployReport
from ..core.tagging import merge_tags, to_cfn_tags

logger = logging.getLogger(__name__)


# Stacks in these states can never be updated in place; they must be deleted and recreated.
UNUSABLE_STACK_STATES = frozenset(
    {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "REVIEW_IN_PROGRESS", "CREATE_FAILED", "DELETE_FAILED"}
)


def _as_stored(template: str) -> str:
    """The template as GetTemplate returns it: CloudFormation stores each non-ASCII character as '?'."""
    return template.strip().encode("ascii", "replace").decode("ascii")


class _TemplateLoader(yaml.SafeLoader):
    """Reads CloudFormation YAML, keeping short-form tags such as !Ref as {"!Ref": value}."""


def _tagged(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        return {f"!{suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"!{suffix}": loader.construct_sequence(node, deep=True)}
    return {f"!{suffix}": loader.construct_mapping(node, deep=True)}  # pyright: ignore[reportArgumentType]


_TemplateLoader.add_multi_constructor("!", _tagged)


def _parsed(template: Any) -> Any:
    if isinstance(template, dict):
        return template
    try:
        return yaml.load(_as_stored(str(template)), Loader=_TemplateLoader)  # noqa: S506 - safe loader subclass
    except yaml.YAMLError:
        return None


def same_template(live: Any, local: str) -> bool:
    """Whether the live template and the local one are the same, ignoring formatting and key order."""
    if isinstance(live, str) and _as_stored(live) == _as_stored(local):
        return True
    parsed = _parsed(live)
    return parsed is not None and parsed == _parsed(local)


def _tags_in(value: Any) -> set[str]:
    """Short-form tag keys anywhere in a parsed template (they cannot be written back as plain YAML)."""
    if isinstance(value, dict):
        return {k for k in value if isinstance(k, str) and k.startswith("!")} | {
            t for v in value.values() for t in _tags_in(v)
        }
    if isinstance(value, list):
        return {t for v in value for t in _tags_in(v)}
    return set()


def lock_table_wanted(cfn_client: Any, stack_name: str, configured: bool | None) -> tuple[bool, str | None]:
    """Decide whether the Terraform backend stack should have a DynamoDB lock table.

    Returns (wanted, warning). With nothing configured a new backend is S3-only, which is cheaper and is what
    Terraform now recommends ("DynamoDB-based locking is deprecated"), and an existing stack that has the table keeps
    it, because dropping the table breaks every Terraform configuration still pointing at it.
    """
    current = _stack_parameter(cfn_client, stack_name, "EnableDynamoDB")
    has_table = current == "true"
    if configured is None:
        return has_table, None
    wanted = configured
    if has_table and not wanted:
        return False, (
            f"Stack '{stack_name}' has a DynamoDB lock table and this deployment removes it. Terraform "
            "configurations that still set dynamodb_table will fail to lock state until they use "
            "`use_lockfile = true` instead."
        )
    return wanted, None


def _stack_parameter(cfn_client: Any, stack_name: str, key: str) -> str | None:
    """A parameter of an existing stack, or None when the stack or parameter does not exist or cannot be read."""
    try:
        stacks = cfn_client.describe_stacks(StackName=stack_name).get("Stacks", [])
    except (ClientError, AttributeError):
        return None
    if not isinstance(stacks, list) or not stacks:
        return None
    for param in stacks[0].get("Parameters", []) or []:
        if isinstance(param, dict) and param.get("ParameterKey") == key:
            return str(param.get("ParameterValue"))
    return None


class CloudFormationService:
    """Deploys and manages foundational CloudFormation stacks with robust waiters and output retrieval."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr: AwsSessionManager = session_mgr

    def deploy_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        template_file: Path | None = None,
        parameters: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
        account_tags: dict[str, str] | None = None,
        template_body: str | None = None,
        on_before_create: Callable[[], None] | None = None,
        termination_protection: bool = False,
    ) -> StackDeployReport:
        """Deploy or update a CloudFormation stack and return a StackDeployReport.

        With `termination_protection`, the stack is protected against accidental deletion once it is deployed.

        Tags are merged according to the Tarmac Tagging Hierarchy:
        Default System Tags (ManagedBy: tarmac) -> org_tags -> account_tags -> tags (stack/custom)
        """
        if template_body is None:
            if template_file is None:
                raise DeploymentError("Either template_file or template_body must be provided.")
            if not template_file.exists():
                raise DeploymentError(f"CloudFormation template not found: {template_file}")
            template_body = template_file.read_text(encoding="utf-8")

        cfn_params = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in (parameters or {}).items()]
        resolved_tags = merge_tags(org_tags, account_tags, tags)
        cfn_tags = to_cfn_tags(resolved_tags)

        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status in UNUSABLE_STACK_STATES:
            logger.warning(
                "Stack '%s' is in %s state and cannot be updated. Deleting broken/unexecuted stack...",
                stack_name,
                stack_status,
            )
            self._delete_broken_stack(cfn_client, stack_name)
            stack_exists = False
        elif stack_status in [None, "DELETE_COMPLETE"]:
            stack_exists = False
        else:
            stack_exists = True

        if not stack_exists and on_before_create:
            on_before_create()

        action = self._execute_deployment(
            cfn_client, stack_name, template_body, cfn_params, cfn_tags, stack_exists
        )
        outputs = self._fetch_stack_outputs(cfn_client, stack_name)
        if termination_protection:
            self.protect_stack(cfn_client, stack_name)

        return StackDeployReport(action=action, outputs=outputs, status="SUCCEEDED")

    def preview_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        template_file: Path | None = None,
        parameters: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
        account_tags: dict[str, str] | None = None,
        template_body: str | None = None,
    ) -> tuple[str, str]:
        """What deploy_stack would do, read-only: (action, detail).

        The action is CREATE, REPLACE (the stack is in a state that forces delete and recreate), UPDATE or
        NO CHANGE. An update names what differs: the template text, which of the given parameters, or the tags.
        Parameters the stack has but that are not given here are not compared.
        """
        if template_body is None:
            if template_file is None:
                raise DeploymentError("Either template_file or template_body must be provided.")
            template_body = template_file.read_text(encoding="utf-8")

        status = self._get_stack_status(cfn_client, stack_name)
        if status in (None, "DELETE_COMPLETE"):
            return "CREATE", ""
        if status in UNUSABLE_STACK_STATES:
            return "REPLACE", f"stack is {status}; it is deleted and created again"

        stack = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        live_params = {
            str(p["ParameterKey"]): str(p.get("ParameterValue", "")) for p in stack.get("Parameters", [])
        }
        changes = [
            f"{key}: {live_params.get(key, '(unset)')} -> {value}"
            for key, value in (parameters or {}).items()
            if live_params.get(key) != str(value)
        ]
        live_body = cfn_client.get_template(StackName=stack_name, TemplateStage="Original").get(
            "TemplateBody"
        )
        if not same_template(live_body, template_body):
            changes.append("template")
        live_tags = {str(tag["Key"]): str(tag["Value"]) for tag in stack.get("Tags", [])}
        if live_tags != merge_tags(org_tags, account_tags, tags):
            changes.append("tags")
        return ("UPDATE", "; ".join(changes)) if changes else ("NO CHANGE", "")

    def is_usable(self, cfn_client: Any, stack_name: str) -> bool:
        """Whether the stack exists in a state that can be updated or imported into."""
        status = self._get_stack_status(cfn_client, stack_name)
        return status not in (None, "DELETE_COMPLETE") and status not in UNUSABLE_STACK_STATES

    @staticmethod
    def resource_ids(cfn_client: Any, stack_name: str) -> set[str]:
        """Logical IDs of the resources the stack manages."""
        pages = cfn_client.get_paginator("list_stack_resources").paginate(StackName=stack_name)
        return {str(r["LogicalResourceId"]) for page in pages for r in page.get("StackResourceSummaries", [])}

    def import_template(
        self, cfn_client: Any, stack_name: str, template: dict[str, Any], adopted: dict[str, Any]
    ) -> str:
        """The template for an IMPORT change set that adopts ``adopted`` (logical ID -> resource).

        An import may not change anything already in the stack, so into a usable stack it is the live template
        plus the adopted resources; for a new stack it is ``template`` with only the adopted resources.
        """
        if not self.is_usable(cfn_client, stack_name):
            return yaml.dump({**template, "Resources": adopted}, sort_keys=False)
        live = _parsed(
            cfn_client.get_template(StackName=stack_name, TemplateStage="Original")["TemplateBody"]
        )
        if not isinstance(live, dict) or any(k.startswith("!") for k in _tags_in(live)):
            raise DeploymentError(
                f"Could not read the live template of stack '{stack_name}' to import into it."
            )
        live["Resources"] = {**(live.get("Resources") or {}), **adopted}
        return yaml.dump(live, sort_keys=False)

    def protect_stack(self, cfn_client: Any, stack_name: str) -> None:
        """Turn on termination protection. Failing to do so never fails a deployment; it is reported instead."""
        try:
            if self._is_protected(cfn_client, stack_name):
                return
            cfn_client.update_termination_protection(StackName=stack_name, EnableTerminationProtection=True)
        except ClientError as e:
            audit(
                "protect",
                f"stack:{stack_name}",
                Outcome.FAILED,
                f"Could not turn on termination protection for '{stack_name}': {aws_error_message(e)}. "
                "If this is AccessDenied, re-run 'tarmac bootstrap' to refresh the deployment permission set.",
            )
            return
        audit(
            "protect",
            f"stack:{stack_name}",
            Outcome.SUCCEEDED,
            f"Turned on termination protection for '{stack_name}'",
        )

    @staticmethod
    def _is_protected(cfn_client: Any, stack_name: str) -> bool:
        stacks = cfn_client.describe_stacks(StackName=stack_name).get("Stacks", [])
        return bool(
            isinstance(stacks, list) and stacks and stacks[0].get("EnableTerminationProtection") is True
        )

    def import_resources_and_deploy_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        template_body: str,
        resources_to_import: list[dict[str, Any]],
        tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
    ) -> StackDeployReport:
        """Create a CloudFormation stack by importing pre-existing AWS resources."""

        resolved_tags = merge_tags(org_tags, tags)
        cfn_tags = to_cfn_tags(resolved_tags)
        change_set_name = f"import-{int(time.time())}"

        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status in UNUSABLE_STACK_STATES:
            logger.warning(
                "Stack '%s' is in %s state. Deleting broken/unexecuted stack before import...",
                stack_name,
                stack_status,
            )
            self._delete_broken_stack(cfn_client, stack_name)

        logger.debug(
            "Creating IMPORT change set '%s' for stack '%s' (%d resources)...",
            change_set_name,
            stack_name,
            len(resources_to_import),
        )
        try:
            cfn_client.create_change_set(
                StackName=stack_name,
                ChangeSetName=change_set_name,
                ChangeSetType="IMPORT",
                TemplateBody=template_body,
                ResourcesToImport=resources_to_import,
                Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            )
            waiter = cfn_client.get_waiter("change_set_create_complete")
            waiter.wait(
                StackName=stack_name,
                ChangeSetName=change_set_name,
                WaiterConfig={"Delay": 3, "MaxAttempts": 30},
            )

            logger.debug("Executing IMPORT change set '%s' on stack '%s'...", change_set_name, stack_name)
            cfn_client.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)

            import_waiter = cfn_client.get_waiter("stack_import_complete")
            import_waiter.wait(
                StackName=stack_name,
                WaiterConfig={"Delay": 5, "MaxAttempts": 60},
            )
            audit(
                "import",
                f"stack:{stack_name}",
                Outcome.SUCCEEDED,
                f"Imported {len(resources_to_import)} existing resource(s) into CloudFormation stack "
                f"'{stack_name}'",
                resource_count=len(resources_to_import),
            )

            if cfn_tags:
                try:
                    logger.debug("Applying tags to imported stack '%s'...", stack_name)
                    cfn_client.update_stack(
                        StackName=stack_name,
                        UsePreviousTemplate=True,
                        Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
                        Tags=cfn_tags,
                    )
                    update_waiter = cfn_client.get_waiter("stack_update_complete")
                    update_waiter.wait(
                        StackName=stack_name,
                        WaiterConfig={"Delay": 3, "MaxAttempts": 30},
                    )
                except ClientError as e:
                    if "No updates are to be performed" not in str(e):
                        logger.warning("Failed to apply tags to stack '%s': %s", stack_name, e)

            outputs = self._fetch_stack_outputs(cfn_client, stack_name)
            return StackDeployReport(action="IMPORTED", outputs=outputs, status="SUCCEEDED")
        except (ClientError, WaiterError) as e:
            reasons = self._change_set_failure_reason(cfn_client, stack_name, change_set_name)
            reasons = reasons or self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
            hint = self._ownership_hint(reasons)
            detail = f"{detail}\n{hint}" if hint else detail
            audit(
                "import",
                f"stack:{stack_name}",
                Outcome.FAILED,
                f"Could not import resources into CloudFormation stack '{stack_name}': {detail}",
            )
            raise DeploymentError(
                f"Failed to import resources into stack '{stack_name}'", details=detail
            ) from e

    def _get_stack_status(self, cfn_client: Any, stack_name: str) -> str | None:
        """Fetch the current CloudFormation stack status, or None if it does not exist."""
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            stacks = resp.get("Stacks", [])
            if stacks:
                return str(stacks[0].get("StackStatus", ""))
            return None
        except ClientError as e:
            if "does not exist" not in aws_error_message(e):
                raise DeploymentError(f"Failed inspecting stack {stack_name}", details=str(e)) from e
            return None

    def _delete_broken_stack(self, cfn_client: Any, stack_name: str) -> None:
        """Delete a stack in an unusable state (e.g. ROLLBACK_COMPLETE, DELETE_FAILED) before recreating it."""
        try:
            logger.debug("Deleting broken stack '%s'...", stack_name)
            try:
                cfn_client.delete_stack(StackName=stack_name)
            except ClientError as e:
                if "TerminationProtection" not in aws_error_message(e):
                    raise
                self._release_protection(cfn_client, stack_name, allowed=True, on_progress=None)
                cfn_client.delete_stack(StackName=stack_name)
            waiter = cfn_client.get_waiter("stack_delete_complete")
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 5, "MaxAttempts": 30})
            audit(
                "delete",
                f"stack:{stack_name}",
                Outcome.SUCCEEDED,
                f"Deleted CloudFormation stack '{stack_name}' that was stuck in an unusable state",
            )
        except (ClientError, WaiterError) as e:
            raise DeploymentError(
                f"Failed to delete broken stack '{stack_name}'",
                details=str(e),
            ) from e

    def delete_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        wait: bool = True,
        on_progress: Callable[[str], None] | None = None,
        release_protection: bool = False,
    ) -> bool:
        """Delete a CloudFormation stack and optionally wait for completion.

        A stack with termination protection is only deleted when the caller passes `release_protection`, meaning the
        user asked for these resources to be removed; protection is then switched off first and that is announced.

        Returns True if the stack was deleted, or False if the stack did not exist.
        """
        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status is None or stack_status == "DELETE_COMPLETE":
            logger.debug("Stack '%s' does not exist or is already deleted.", stack_name)
            return False
        if self._is_protected(cfn_client, stack_name):
            self._release_protection(cfn_client, stack_name, release_protection, on_progress)

        logger.debug("Deleting CloudFormation stack '%s' (current status: %s)...", stack_name, stack_status)
        if on_progress:
            on_progress(f"Waiting for CloudFormation stack '{stack_name}' deletion to complete...")

        try:
            cfn_client.delete_stack(StackName=stack_name)
            if wait:
                waiter = cfn_client.get_waiter("stack_delete_complete")
                waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            audit(
                "delete",
                f"stack:{stack_name}",
                Outcome.SUCCEEDED if wait else Outcome.SKIPPED,
                f"Deleted CloudFormation stack '{stack_name}'"
                if wait
                else f"Requested deletion of CloudFormation stack '{stack_name}' without waiting",
            )
            return True
        except (ClientError, WaiterError) as e:
            reasons = self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
            audit(
                "delete",
                f"stack:{stack_name}",
                Outcome.FAILED,
                f"Could not delete CloudFormation stack '{stack_name}': {detail}",
            )
            raise DeploymentError(f"Failed to delete stack '{stack_name}'", details=detail) from e

    @staticmethod
    def _release_protection(
        cfn_client: Any, stack_name: str, allowed: bool, on_progress: Callable[[str], None] | None
    ) -> None:
        if not allowed:
            raise DeploymentError(
                f"Stack '{stack_name}' has termination protection and was not deleted.",
                details="Run the teardown command that removes these resources, or turn protection off yourself.",
            )
        message = (
            f"Turning off termination protection on '{stack_name}': it protects against accidental deletion, "
            "and this teardown was asked to remove it."
        )
        if on_progress:
            on_progress(message)
        audit("unprotect", f"stack:{stack_name}", Outcome.SUCCEEDED, message)
        try:
            cfn_client.update_termination_protection(StackName=stack_name, EnableTerminationProtection=False)
        except ClientError as e:
            raise DeploymentError(
                f"Could not turn off termination protection on '{stack_name}'", details=str(e)
            ) from e

    @staticmethod
    def _change_set_failure_reason(cfn_client: Any, stack_name: str, change_set_name: str) -> str:
        """The StatusReason CloudFormation gives a change set that failed to build (empty if unavailable)."""
        try:
            described = cfn_client.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        except (ClientError, WaiterError, BotoCoreError):
            return ""
        if described.get("Status") == "FAILED":
            return str(described.get("StatusReason", ""))
        return ""

    @staticmethod
    def _ownership_hint(reason: str) -> str:
        """Plain-language next step when a resource already belongs to a different CloudFormation stack."""
        match = re.search(r"already exists in stack (\S+)", reason)
        if not match:
            return ""
        owner = match.group(1)
        return (
            f"That resource is already managed by CloudFormation stack {owner}. Tarmac names its stacks after "
            "organization.name in organization.yaml, so if that name was changed after an earlier deploy, set it "
            "back to the original value (the prefix of the stack named above)."
        )

    def _fetch_failure_reasons(self, cfn_client: Any, stack_name: str) -> str:
        """Retrieve failure causes from recent stack events and pre-deployment validation."""
        reasons: list[str] = []
        try:
            if hasattr(cfn_client, "describe_events"):
                try:
                    op_events = cfn_client.describe_events(StackName=stack_name)
                    for ev in op_events.get("OperationEvents", []):
                        if ev.get("EventType") == "VALIDATION_ERROR":
                            res_id = str(
                                ev.get("LogicalResourceId") or ev.get("ValidationPath") or "Template"
                            )
                            v_reason = str(
                                ev.get("ResourceStatusReason") or ev.get("ValidationStatusReason") or ""
                            )
                            if v_reason:
                                reasons.append(f"{res_id}: {v_reason}")
                except AWS_ERRORS as exc:  # best effort: extra failure detail only
                    logger.debug("Could not read change-set validation events for '%s': %s", stack_name, exc)

            events_resp = cfn_client.describe_stack_events(StackName=stack_name)
            for ev in events_resp.get("StackEvents", []):
                status = str(ev.get("ResourceStatus", ""))
                reason = str(ev.get("ResourceStatusReason", ""))
                if "FAILED" in status and reason and "User Initiated" not in reason:
                    if "Validation failed with" in reason and reasons:
                        continue
                    res_id = str(ev.get("LogicalResourceId", ""))
                    reasons.append(f"{res_id}: {reason}")
            if reasons:
                return "; ".join(reasons[:3])
        except ClientError:
            pass
        return ""

    def _execute_deployment(
        self,
        cfn_client: Any,
        stack_name: str,
        template_body: str,
        cfn_params: list[dict[str, str]],
        cfn_tags: list[dict[str, str]],
        stack_exists: bool,
    ) -> Literal["CREATED", "UPDATED", "NO_CHANGES"]:
        """Execute stack creation or update and wait for completion."""
        action: Literal["CREATED", "UPDATED", "NO_CHANGES"] = "UPDATED" if stack_exists else "CREATED"
        request = {
            "StackName": stack_name,
            "TemplateBody": template_body,
            "Parameters": cfn_params,
            "Capabilities": ["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            "Tags": cfn_tags,
        }
        try:
            if not stack_exists:
                logger.debug("Creating CloudFormation stack '%s'...", stack_name)
                cfn_client.create_stack(**request)
                waiter = cfn_client.get_waiter("stack_create_complete")
            else:
                logger.debug("Updating CloudFormation stack '%s'...", stack_name)
                cfn_client.update_stack(**request)
                waiter = cfn_client.get_waiter("stack_update_complete")

            logger.debug("Waiting for stack '%s' to complete...", stack_name)
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 60})
            audit(
                "create" if action == "CREATED" else "update",
                f"stack:{stack_name}",
                Outcome.SUCCEEDED,
                f"{'Created' if action == 'CREATED' else 'Updated'} CloudFormation stack '{stack_name}'",
            )
            return action

        except ClientError as e:
            if "No updates are to be performed" in aws_error_message(e):
                audit(
                    "update",
                    f"stack:{stack_name}",
                    Outcome.UNCHANGED,
                    f"CloudFormation stack '{stack_name}' is already up to date",
                )
                return "NO_CHANGES"
            audit(
                "create" if action == "CREATED" else "update",
                f"stack:{stack_name}",
                Outcome.FAILED,
                f"Could not {'create' if action == 'CREATED' else 'update'} CloudFormation stack "
                f"'{stack_name}': {aws_error_message(e)}",
            )
            raise DeploymentError(
                f"Failed to deploy stack '{stack_name}'",
                details=aws_error_message(e),
            ) from e
        except WaiterError as e:
            reasons = self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
            audit(
                "create" if action == "CREATED" else "update",
                f"stack:{stack_name}",
                Outcome.FAILED,
                f"CloudFormation stack '{stack_name}' did not finish: {detail}",
            )
            raise DeploymentError(f"Waiter timed out waiting for stack '{stack_name}'", details=detail) from e

    def _fetch_stack_outputs(self, cfn_client: Any, stack_name: str) -> dict[str, str]:
        """Retrieve stack output parameters."""
        outputs: dict[str, str] = {}
        try:
            desc = cfn_client.describe_stacks(StackName=stack_name)
            for out in desc["Stacks"][0].get("Outputs", []):
                outputs[out["OutputKey"]] = out["OutputValue"]
        except ClientError as e:
            logger.warning("Could not retrieve outputs for stack %s: %s", stack_name, e)
        return outputs
