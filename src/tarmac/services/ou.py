"""Organizational Unit (OU) Tree Reconciliation Service."""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_schema import OUDef
from ..core.exceptions import OUManagementError
from ..core.models import OUSyncReport

logger = logging.getLogger(__name__)


class OUService:
    """Manages idempotent creation, discovery, and reconciliation of OU structures."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr: AwsSessionManager = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")

    def get_root_id(self) -> str:
        """Fetch the organization root ID."""
        try:
            resp = self.org_client.list_roots()
            roots = resp.get("Roots", [])
            if not roots:
                raise OUManagementError("No AWS Organizations root found in current account.")
            root_id: str = roots[0]["Id"]
            return root_id
        except ClientError as e:
            raise OUManagementError("Failed to query organization roots", details=str(e)) from e

    def list_existing_ous_for_parent(self, parent_id: str) -> dict[str, str]:
        """List immediate child OUs for a given parent. Returns {Name: Id}."""
        ou_map: dict[str, str] = {}
        try:
            paginator = self.org_client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get("OrganizationalUnits", []):
                    ou_map[ou["Name"]] = ou["Id"]
            return ou_map
        except ClientError as e:
            raise OUManagementError(f"Failed to list OUs for parent '{parent_id}'", details=str(e)) from e

    def list_all_ous(self, parent_id: str | None = None) -> dict[str, str]:
        """Recursively discover all OUs across the entire organization tree."""
        root_id = parent_id or self.get_root_id()
        all_ous: dict[str, str] = {}
        to_visit = [root_id]
        visited: set[str] = set()
        while to_visit:
            curr = to_visit.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            direct = self.list_existing_ous_for_parent(curr)
            all_ous.update(direct)
            for child_id in direct.values():
                if child_id not in visited:
                    to_visit.append(child_id)
        return all_ous

    def sync_ou_structure(self, desired_ous: list[OUDef], parent_id: str | None = None) -> OUSyncReport:
        """Idempotently reconcile the desired OU hierarchy against AWS Organizations.

        Returns an OUSyncReport containing all synced, created, and existing OUs.
        """
        root_id = parent_id or self.get_root_id()
        existing_ous = self.list_existing_ous_for_parent(root_id)
        synced: dict[str, str] = {}
        created: list[str] = []
        already_existing: list[str] = []

        for ou_def in desired_ous:
            ou_name = ou_def.name
            if ou_name in existing_ous:
                ou_id = existing_ous[ou_name]
                logger.debug("OU '%s' already exists (ID: %s)", ou_name, ou_id)
                synced[ou_name] = ou_id
                already_existing.append(ou_name)
            else:
                ou_id = self._create_ou(root_id, ou_name)
                synced[ou_name] = ou_id
                created.append(ou_name)

            if ou_def.children:
                child_report = self.sync_ou_structure(ou_def.children, parent_id=ou_id)
                synced.update(child_report.synced_ous)
                created.extend(child_report.created_ous)
                already_existing.extend(child_report.existing_ous)

        return OUSyncReport(synced_ous=synced, created_ous=created, existing_ous=already_existing)

    def _create_ou(self, parent_id: str, ou_name: str) -> str:
        """Helper to create a single OU and handle race conditions."""
        try:
            logger.info("Creating OU '%s' under parent %s...", ou_name, parent_id)
            resp = self.org_client.create_organizational_unit(
                ParentId=parent_id,
                Name=ou_name,
            )
            ou_id: str = resp["OrganizationalUnit"]["Id"]
            logger.info("Successfully created OU '%s' (ID: %s)", ou_name, ou_id)
            return ou_id
        except ClientError as e:
            if e.response["Error"]["Code"] == "DuplicateOrganizationalUnitException":
                refreshed = self.list_existing_ous_for_parent(parent_id)
                if ou_name in refreshed:
                    return refreshed[ou_name]
            raise OUManagementError(
                f"Failed to create OU '{ou_name}' under parent '{parent_id}'",
                details=e.response["Error"].get("Message", str(e)),
            ) from e
