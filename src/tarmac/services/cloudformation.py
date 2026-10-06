"""CloudFormation Stack Deployment Service."""

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from botocore.exceptions import ClientError, WaiterError

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import DeploymentError
from ..core.models import StackDeployReport
from ..core.tagging import merge_tags, to_cfn_tags

logger = logging.getLogger(__name__)


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
        dry_run: bool = False,
        template_body: str | None = None,
        on_before_create: Callable[[], None] | None = None,
    ) -> StackDeployReport:
        """Deploy or update a CloudFormation stack and return a StackDeployReport.

        Tags are merged according to the Tarmac Tagging Hierarchy:
        Default System Tags (ManagedBy: tarmac) -> org_tags -> account_tags -> tags (stack/custom)
        """
        template_name = template_file.name if template_file else "synthesized-template"
        if dry_run:
            logger.info("[DRY-RUN] Would deploy stack '%s' using template '%s'", stack_name, template_name)
            return StackDeployReport(
                stack_name=stack_name, action="SIMULATED", outputs={}, status="SIMULATED"
            )

        if template_body is None:
            if template_file is None:
                raise DeploymentError("Either template_file or template_body must be provided.")
            if not template_file.exists():
                raise DeploymentError(f"CloudFormation template not found: {template_file}")
            with open(template_file, encoding="utf-8") as f:
                template_body = f.read()

        cfn_params = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in (parameters or {}).items()]
        resolved_tags = merge_tags(org_tags, account_tags, tags)
        cfn_tags = to_cfn_tags(resolved_tags)

        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status in ("ROLLBACK_COMPLETE", "REVIEW_IN_PROGRESS"):
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

        return StackDeployReport(stack_name=stack_name, action=action, outputs=outputs, status="SUCCEEDED")

    def import_resources_and_deploy_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        template_body: str,
        resources_to_import: list[dict[str, Any]],
        tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
        account_tags: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> StackDeployReport:
        """Create a CloudFormation stack by importing pre-existing AWS resources."""
        if dry_run:
            logger.info(
                "[DRY-RUN] Would create CloudFormation stack '%s' importing %d pre-existing resources",
                stack_name,
                len(resources_to_import),
            )
            return StackDeployReport(stack_name=stack_name, action="IMPORTED", outputs={}, status="SUCCEEDED")

        resolved_tags = merge_tags(org_tags, account_tags, tags)
        cfn_tags = to_cfn_tags(resolved_tags)
        change_set_name = f"import-{int(time.time())}"

        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status in ("ROLLBACK_COMPLETE", "REVIEW_IN_PROGRESS"):
            logger.warning(
                "Stack '%s' is in %s state. Deleting broken/unexecuted stack before import...",
                stack_name,
                stack_status,
            )
            self._delete_broken_stack(cfn_client, stack_name)

        logger.info(
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

            logger.info("Executing IMPORT change set '%s' on stack '%s'...", change_set_name, stack_name)
            cfn_client.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)

            import_waiter = cfn_client.get_waiter("stack_import_complete")
            import_waiter.wait(
                StackName=stack_name,
                WaiterConfig={"Delay": 5, "MaxAttempts": 60},
            )
            logger.info("Successfully imported resources into stack '%s'.", stack_name)

            if cfn_tags:
                try:
                    logger.info("Applying tags to imported stack '%s'...", stack_name)
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
            return StackDeployReport(
                stack_name=stack_name, action="IMPORTED", outputs=outputs, status="SUCCEEDED"
            )
        except (ClientError, WaiterError) as e:
            reasons = self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
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
            if "does not exist" not in e.response["Error"]["Message"]:
                raise DeploymentError(f"Failed inspecting stack {stack_name}", details=str(e)) from e
            return None

    def _delete_broken_stack(self, cfn_client: Any, stack_name: str) -> None:
        """Delete a stack in ROLLBACK_COMPLETE or REVIEW_IN_PROGRESS state before recreating it."""
        try:
            logger.info("Deleting broken stack '%s'...", stack_name)
            cfn_client.delete_stack(StackName=stack_name)
            waiter = cfn_client.get_waiter("stack_delete_complete")
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 5, "MaxAttempts": 30})
            logger.info("Successfully deleted broken stack '%s'.", stack_name)
        except (ClientError, WaiterError) as e:
            raise DeploymentError(
                f"Failed to delete broken stack '{stack_name}' in ROLLBACK_COMPLETE state",
                details=str(e),
            ) from e

    def delete_stack(
        self,
        cfn_client: Any,
        stack_name: str,
        wait: bool = True,
        on_progress: Callable[[str], None] | None = None,
    ) -> bool:
        """Delete a CloudFormation stack and optionally wait for completion.

        Returns True if the stack was deleted, or False if the stack did not exist.
        """
        stack_status = self._get_stack_status(cfn_client, stack_name)
        if stack_status is None or stack_status == "DELETE_COMPLETE":
            logger.debug("Stack '%s' does not exist or is already deleted.", stack_name)
            return False

        logger.info("Deleting CloudFormation stack '%s' (current status: %s)...", stack_name, stack_status)
        if on_progress:
            on_progress(f"Waiting for CloudFormation stack '{stack_name}' deletion to complete...")

        try:
            cfn_client.delete_stack(StackName=stack_name)
            if wait:
                waiter = cfn_client.get_waiter("stack_delete_complete")
                waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            logger.info("Successfully deleted CloudFormation stack '%s'.", stack_name)
            return True
        except (ClientError, WaiterError) as e:
            reasons = self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
            raise DeploymentError(f"Failed to delete stack '{stack_name}'", details=detail) from e

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
                except Exception:
                    pass

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
        try:
            if not stack_exists:
                logger.info("Creating CloudFormation stack '%s'...", stack_name)
                cfn_client.create_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=cfn_params,
                    Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
                    Tags=cfn_tags,
                )
                waiter = cfn_client.get_waiter("stack_create_complete")
            else:
                logger.info("Updating CloudFormation stack '%s'...", stack_name)
                cfn_client.update_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=cfn_params,
                    Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
                    Tags=cfn_tags,
                )
                waiter = cfn_client.get_waiter("stack_update_complete")

            logger.info("Waiting for stack '%s' to complete...", stack_name)
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 60})
            logger.info("Stack '%s' deployed successfully.", stack_name)
            return action

        except ClientError as e:
            if "No updates are to be performed" in e.response["Error"]["Message"]:
                logger.info("Stack '%s' is already up to date (no changes).", stack_name)
                return "NO_CHANGES"
            raise DeploymentError(
                f"Failed to deploy stack '{stack_name}'",
                details=e.response["Error"].get("Message", str(e)),
            ) from e
        except WaiterError as e:
            reasons = self._fetch_failure_reasons(cfn_client, stack_name)
            detail = f"{e} (Root cause: {reasons})" if reasons else str(e)
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
