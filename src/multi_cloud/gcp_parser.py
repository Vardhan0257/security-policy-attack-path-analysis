"""
GCP IAM parser scaffold for Phase 3.4.
Parses GCP bindings and role definitions into normalized model.
"""
from typing import Dict, Any, List, Set


class GCPIAMParser:
    """Parse GCP IAM policy bindings and role definitions.

    Responsibilities:
    - parse `bindings` from a Policy into principal -> role mapping
    - parse custom role definitions into permission lists
    - normalize permission strings
    - flatten permission lists and match against builtin roles
    """

    def parse_policy_bindings(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        bindings = policy.get("bindings", [])
        normalized = []
        for b in bindings:
            role = b.get("role")
            members = b.get("members", [])
            for m in members:
                normalized.append({"principal": m, "role": role})
        return normalized

    def parse_custom_role(self, role_def: Dict[str, Any]) -> Dict[str, Any]:
        role_id = role_def.get("name") or role_def.get("roleId")
        title = role_def.get("title") or role_def.get("displayName")
        permissions = role_def.get("includedPermissions") or role_def.get("permissions") or []
        return {"id": role_id, "title": title, "permissions": permissions}

    def normalize_permission(self, perm: str) -> str:
        """Normalize a GCP permission token.

        For now this is identity, but we normalize common prefixes or wildcards later.
        """
        if not perm:
            return perm
        # strip trailing wildcards like "*" and keep base token for matching heuristics
        if perm.endswith(".*"):
            return perm[:-2] + ":*"
        return perm

    def role_permissions_set(self, parsed_role: Dict[str, Any]) -> Set[str]:
        """Flatten includedPermissions into a normalized set."""
        perms = parsed_role.get("permissions", [])
        out: Set[str] = set()
        for p in perms:
            normalized = self.normalize_permission(p)
            out.add(normalized)
        return out

    def match_builtin_role(self, parsed_role: Dict[str, Any], builtin_map: Dict[str, Set[str]]) -> str:
        """Attempt to match custom role to a known builtin role by overlap.

        Returns the builtin role name or empty string.
        """
        role_perms = self.role_permissions_set(parsed_role)
        for name, perms in builtin_map.items():
            if not perms:
                continue
            overlap = len(role_perms & perms)
            if overlap >= max(1, len(perms) // 2):
                return name
        return ""


__all__ = ["GCPIAMParser"]
