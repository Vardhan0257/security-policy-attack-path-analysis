"""Basic tests for multi-cloud scaffolding (Phase 3.4).
These tests are placeholders that exercise the import surface and basic behavior.
We'll expand coverage with realistic fixtures next.
"""
from src.multi_cloud.azure_parser import AzureRBACParser
from src.multi_cloud.gcp_parser import GCPIAMParser
from src.multi_cloud.compare import MultiCloudComparator


def test_parsers_and_comparator_import():
    az = AzureRBACParser()
    gcp = GCPIAMParser()
    cmp = MultiCloudComparator()

    # basic parse skeleton
    role = {"id": "role1", "properties": {"roleName": "Reader", "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/read"]}]}}
    parsed = az.parse_role_definition(role)
    assert parsed["name"] == "Reader"

    policy = {"bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]}
    bindings = gcp.parse_policy_bindings(policy)
    assert bindings[0]["role"] == "roles/viewer"

    # comparator should run without error on minimal inputs
    cmp.compare_roles([parsed], [{"id": "roles/viewer", "title": "Viewer", "permissions": ["resourcemanager.projects.get"]}])


def test_azure_role_actions_and_matching():
    az = AzureRBACParser()
    # role with multiple permission blocks, dataActions and notActions
    role = {
        "id": "/subscriptions/000/providers/Microsoft.Authorization/roleDefinitions/reader",
        "properties": {
            "displayName": "CustomReader",
            "permissions": [
                {"actions": ["Microsoft.Storage/storageAccounts/read", "Microsoft.Compute/virtualMachines/*"], "notActions": ["Microsoft.Compute/virtualMachines/delete"]},
                {"dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]}
            ]
        }
    }
    parsed = az.parse_role_definition(role)
    actions = az.role_actions_set(parsed)
    # normalized actions should include storageAccounts:read and virtualMachines:*
    assert "storageAccounts:read" in actions
    assert any(a.startswith("virtualMachines:") for a in actions)

    # try matching against a small builtin map
    builtin_map = {
        "Reader": {"storageAccounts:read", "virtualMachines:read", "resourcemanager:resources/read"},
        "Contributor": {"storageAccounts:*", "virtualMachines:*"},
    }
    matched = az.match_builtin_role(parsed, builtin_map)
    # should match at least Contributor (wildcard overlap)
    assert matched in {"Reader", "Contributor"}


def test_gcp_role_permissions_and_matching():
    gcp = GCPIAMParser()
    # custom role with permissions and wildcard
    role = {
        "name": "projects/123/roles/customRole",
        "title": "CustomViewer",
        "includedPermissions": [
            "resourcemanager.projects.get",
            "storage.buckets.get",
            "compute.instances.*"
        ]
    }
    parsed = gcp.parse_custom_role(role)
    perms = gcp.role_permissions_set(parsed)
    assert "resourcemanager.projects.get" in perms
    assert any(p.startswith("compute.instances") for p in perms)

    builtin_map = {
        "Viewer": {"resourcemanager.projects.get", "storage.buckets.get"},
        "Editor": {"resourcemanager.projects.update", "compute.instances.*"},
    }
    matched = gcp.match_builtin_role(parsed, builtin_map)
    assert matched in {"Viewer", "Editor"}


def test_compare_roles_detailed_and_assignments():
    from src.multi_cloud.compare import MultiCloudComparator

    cmp = MultiCloudComparator()
    # azure role with two permissions
    azure_roles = [
        {"id": "r1", "name": "Reader", "permissions": [{"actions": ["storageAccounts:read"]}]},
        {"id": "r2", "name": "CustomWrite", "permissions": [{"actions": ["storageAccounts:write", "virtualMachines:*"]}]},
    ]
    # gcp roles list where Reader exists but missing write perm
    gcp_roles = [
        {"id": "roles/viewer", "title": "Reader", "permissions": ["storage.buckets.get"]},
        {"id": "roles/customWrite", "title": "CustomWrite", "permissions": ["storage.buckets.update"]},
    ]
    detailed = cmp.compare_roles_detailed(azure_roles, gcp_roles)
    # should report missing permissions for Reader and CustomWrite
    assert any(d["azure_role"] == "Reader" and d["missing_permissions"] for d in detailed)

    # assignments
    azure_assignments = [{"principal": "user:alice@example.com", "role_definition_id": "r1"}]
    gcp_bindings = [{"principal": "user:alice@example.com", "role": "roles/viewer"}]
    assign_issues = cmp.compare_assignments_detailed(azure_assignments, gcp_bindings)
    # roles differ (r1 != roles/viewer) should be flagged
    assert assign_issues and assign_issues[0]["issue"] == "role-mismatch"


__all__ = ["test_parsers_and_comparator_import"]
