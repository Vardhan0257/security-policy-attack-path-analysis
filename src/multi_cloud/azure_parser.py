"""
Azure RBAC parser skeleton for Phase 3.4.
Provides simple parsing utilities for Azure role definitions and assignments.

This is a scaffold — we'll expand parsers, unit tests, and integration next.
"""
from typing import Dict, List, Any, Set


class AzureRBACParser:
    """Parse Azure role definitions and role assignments into a normalized model.

    Responsibilities:
    - parse role definition JSON into `role_id -> permissions` mapping
    - parse role assignment objects and map principals to roles
    - provide helper to convert Azure permission actions into normalized permission strings
    - flatten permission blocks and handle wildcards
    """

    def parse_role_definition(self, role_def: Dict[str, Any]) -> Dict[str, Any]:
        """Return a normalized role dict with id, name, and allowed actions.

        The returned `permissions` is a list of permission blocks as in ARM roleDefinition
        but the helper `role_actions_set` can be used to get a flattened set of actions.
        """
        role_id = role_def.get("id") or role_def.get("name")
        props = role_def.get("properties", {})
        role_name = role_def.get("roleName") or props.get("roleName") or props.get("displayName")
        permissions = []
        for perm in props.get("permissions", []):
            actions = perm.get("actions", [])
            not_actions = perm.get("notActions", [])
            data_actions = perm.get("dataActions", [])
            not_data_actions = perm.get("notDataActions", [])
            permissions.append({
                "actions": actions,
                "notActions": not_actions,
                "dataActions": data_actions,
                "notDataActions": not_data_actions,
            })
        return {"id": role_id, "name": role_name, "permissions": permissions}

    def parse_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Return normalized assignment: principal -> role id/name."""
        props = assignment.get("properties", {})
        principal = props.get("principalId") or assignment.get("principalId") or props.get("principalName")
        role_def_id = props.get("roleDefinitionId") or assignment.get("roleDefinitionId")
        scope = props.get("scope") or assignment.get("scope")
        return {"principal": principal, "role_definition_id": role_def_id, "scope": scope}

    def normalize_action(self, action: str) -> str:
        """Normalize Azure action string to a compact representation.

        Example: "Microsoft.Storage/storageAccounts/read" -> "storageAccounts:read"
        Wildcards are preserved as `*` in the resource or operation position.
        """
        if not action or "/" not in action:
            return action
        try:
            # Prefer the resource segment after the provider, e.g.
            # Microsoft.Storage/storageAccounts/read -> resource=storageAccounts, op=read
            parts = action.split("/")
            if len(parts) >= 2:
                resource = parts[1]
                op = parts[-1]
                return f"{resource}:{op}"
            # Fallback to provider-based extraction
            provider_and_resource, op = action.split("/", 1)
            resource = provider_and_resource.split(".")[-1]
            if "/" in op:
                op = op.split("/")[-1]
            return f"{resource}:{op}"
        except Exception:
            return action

    def role_actions_set(self, parsed_role: Dict[str, Any]) -> Set[str]:
        """Return a flattened set of normalized actions for a parsed role definition.

        - Expands `actions` and `dataActions` blocks
        - Includes `notActions`/`notDataActions` only for informational purposes (not removed)
        """
        perms = parsed_role.get("permissions", [])
        actions: Set[str] = set()
        for block in perms:
            for a in block.get("actions", []) + block.get("dataActions", []):
                normalized = self.normalize_action(a)
                actions.add(normalized)
        return actions

    def match_builtin_role(self, parsed_role: Dict[str, Any], builtin_map: Dict[str, Set[str]]) -> str:
        """Try to match a parsed role to a builtin role by comparing permission subsets.

        `builtin_map` is a mapping role_name -> set(normalized permissions).
        Returns the matched builtin name or empty string if none found.
        """
        role_actions = self.role_actions_set(parsed_role)
        for name, perms in builtin_map.items():
            # if role_actions contains at least half of builtin perms, treat as a match
            if not perms:
                continue
            overlap = len(role_actions & perms)
            if overlap >= max(1, len(perms) // 2):
                return name
        return ""


__all__ = ["AzureRBACParser"]
