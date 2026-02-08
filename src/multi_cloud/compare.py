"""
Multi-cloud comparator for Phase 3.4.
Detects policy divergence between Azure and GCP normalized representations.

This module provides a simple comparator API to be expanded with more heuristics.
"""
from typing import Dict, Any, List, Set


class MultiCloudComparator:
    """Compare normalized IAM/role models across clouds.

    Public methods:
    - `compare_roles(azure_roles, gcp_roles)` -> list of divergences
    - `compare_assignments(azure_assignments, gcp_bindings)` -> list of mismatches
    """

    def compare_roles(self, azure_roles: List[Dict[str, Any]], gcp_roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a list of role comparison results.

        Each result contains 'azure_role', 'gcp_role' (if matched) and 'differences'.
        """
        results = []
        gcp_by_title = {r.get("title") or r.get("id"): r for r in gcp_roles}
        for a in azure_roles:
            a_name = a.get("name") or a.get("id")
            match = gcp_by_title.get(a_name)
            diffs = []
            if not match:
                diffs.append("no-equivalent-gcp-role")
            else:
                # naive permission diff
                a_perms = {p for perm_block in a.get("permissions", []) for p in perm_block.get("actions", [])}
                g_perms = set(match.get("permissions", []))
                missing_in_gcp = sorted(list(a_perms - g_perms))
                extra_in_gcp = sorted(list(g_perms - a_perms))
                if missing_in_gcp:
                    diffs.append({"missing_in_gcp": missing_in_gcp})
                if extra_in_gcp:
                    diffs.append({"extra_in_gcp": extra_in_gcp})
            results.append({"azure_role": a_name, "gcp_role": match.get("id") if match else None, "differences": diffs})
        return results

    def compare_assignments(self, azure_assignments: List[Dict[str, Any]], gcp_bindings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compare principal-role mappings across clouds and report mismatches."""
        results = []
        gcp_map = {(b.get("principal"), b.get("role")) for b in gcp_bindings}
        for a in azure_assignments:
            principal = a.get("principal")
            role = a.get("role_definition_id") or a.get("role")
            if (principal, role) not in gcp_map:
                results.append({"principal": principal, "azure_role": role, "status": "missing-in-gcp"})
        return results

    def _permission_set_from_azure(self, azure_role: Dict[str, Any]) -> Set[str]:
        """Helper: flatten azure permission blocks into a set of normalized strings."""
        perms = set()
        for block in azure_role.get("permissions", []):
            for a in block.get("actions", []) + block.get("dataActions", []):
                # assume normalized already (e.g., storageAccounts:read)
                perms.add(a)
        return perms

    def _permission_set_from_gcp(self, gcp_role: Dict[str, Any]) -> Set[str]:
        """Helper: flatten gcp role permissions into a set (identity normalization)."""
        return set(gcp_role.get("permissions", []))

    def compare_roles_detailed(self, azure_roles: List[Dict[str, Any]], gcp_roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return detailed role comparison with diff scores and severity.

        Each entry contains:
        - azure_role, gcp_role (ids)
        - missing_permissions, extra_permissions
        - divergence_score (0-100) where higher means more divergent
        - severity: informational/low/medium/high
        """
        results = []
        gcp_by_title = {r.get("title") or r.get("id"): r for r in gcp_roles}
        for a in azure_roles:
            a_name = a.get("name") or a.get("id")
            match = gcp_by_title.get(a_name)
            a_perms = self._permission_set_from_azure(a)
            if match:
                g_perms = self._permission_set_from_gcp(match)
            else:
                g_perms = set()
            missing = sorted(list(a_perms - g_perms))
            extra = sorted(list(g_perms - a_perms))
            # divergence score: union size scaled by mismatch fraction
            union_len = len(a_perms | g_perms) or 1
            diff_len = len(missing) + len(extra)
            divergence_score = int((diff_len / union_len) * 100)
            if divergence_score >= 70:
                severity = "high"
            elif divergence_score >= 40:
                severity = "medium"
            elif divergence_score >= 10:
                severity = "low"
            else:
                severity = "informational"
            results.append({
                "azure_role": a_name,
                "gcp_role": match.get("id") if match else None,
                "missing_permissions": missing,
                "extra_permissions": extra,
                "divergence_score": divergence_score,
                "severity": severity,
            })
        return results

    def compare_assignments_detailed(self, azure_assignments: List[Dict[str, Any]], gcp_bindings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compare assignments and flag cross-cloud principal-role mismatches with context."""
        results = []
        # map principals to set of roles in GCP
        gcp_map = {}
        for b in gcp_bindings:
            p = b.get("principal")
            r = b.get("role")
            gcp_map.setdefault(p, set()).add(r)
        for a in azure_assignments:
            principal = a.get("principal")
            role = a.get("role_definition_id") or a.get("role")
            gcp_roles = gcp_map.get(principal, set())
            if role not in gcp_roles:
                results.append({
                    "principal": principal,
                    "azure_role": role,
                    "gcp_roles": sorted(list(gcp_roles)),
                    "issue": "role-mismatch",
                })
        return results


__all__ = ["MultiCloudComparator"]
