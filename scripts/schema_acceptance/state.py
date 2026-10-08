"""Prepare and inspect acceptance-owned state inside ``manage.py cms shell``."""

import json
import os
import time

from casbin_adapter.models import CasbinRule
from django.db import transaction

from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
    AuthzSchemaSource,
)

PREFIX = "acceptance_"
ROLE = "acceptance_editor"
ROLE_SUBJECT = f"role^{ROLE}"
USER_SUBJECT = "user^acceptance_alice"
SCOPE = "course-v1^course-v1:Acceptance+Test+Run"
UNMANAGED_ROLE = "role^unmanaged_acceptance"


def snapshot():
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    roles = list(
        AuthzRoleDefinition.objects.filter(role_id__startswith=PREFIX)
        .order_by("role_id")
        .values("role_id", "display_name", "hidden")
    )
    permissions = list(
        AuthzPermissionDefinition.objects.filter(namespace=PREFIX.rstrip("_"))
        .order_by("name")
        .values_list("name", flat=True)
    )
    policies = list(
        CasbinRule.objects.filter(v0__startswith=f"role^{PREFIX}")
        .order_by("ptype", "v0", "v1", "v2")
        .values_list("ptype", "v0", "v1", "v2", "v3")
    )
    assignments = list(
        CasbinRule.objects.filter(ptype="g", v1=ROLE_SUBJECT).order_by("v0", "v1", "v2").values_list("v0", "v1", "v2")
    )
    sources = list(
        AuthzSchemaSource.objects.filter(module__startswith="acceptance_schema")
        .order_by("module")
        .values_list("module", flat=True)
    )
    unmanaged = list(
        CasbinRule.objects.filter(v0=UNMANAGED_ROLE)
        .order_by("ptype", "v1", "v2")
        .values_list("ptype", "v0", "v1", "v2", "v3")
    )
    return {
        "roles": roles,
        "permissions": permissions,
        "policies": policies,
        "assignments": assignments,
        "sources": sources,
        "unmanaged": unmanaged,
        "allows_view": enforcer.enforce(USER_SUBJECT, "act^acceptance.view", SCOPE),
        "allows_edit": enforcer.enforce(USER_SUBJECT, "act^acceptance.edit", SCOPE),
    }


def clean():
    CasbinRule.objects.filter(v0__startswith=f"role^{PREFIX}").delete()
    CasbinRule.objects.filter(ptype="g", v1__startswith=f"role^{PREFIX}").delete()
    CasbinRule.objects.filter(v0=UNMANAGED_ROLE).delete()
    AuthzRoleDefinition.objects.filter(role_id__startswith=PREFIX).delete()
    AuthzPermissionDefinition.objects.filter(namespace=PREFIX.rstrip("_")).delete()
    AuthzPermissionCategory.objects.filter(category_id__startswith=PREFIX).delete()
    AuthzSchemaSource.objects.filter(module__startswith="acceptance_schema").delete()
    AuthzEnforcer.get_enforcer().load_policy()


def assign():
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    added = enforcer.add_grouping_policy(USER_SUBJECT, ROLE_SUBJECT, SCOPE)
    if not added:
        raise AssertionError("acceptance assignment already existed")


def seed_policy():
    CasbinRule.objects.create(
        ptype="p",
        v0=ROLE_SUBJECT,
        v1="act^acceptance.view",
        v2="course-v1^*",
        v3="allow",
    )


def seed_unmanaged():
    CasbinRule.objects.create(
        ptype="p",
        v0=UNMANAGED_ROLE,
        v1="act^acceptance.view",
        v2="course-v1^*",
        v3="allow",
    )


def seed_definitions(conflicting=False, orphan=False):
    category = AuthzPermissionCategory.objects.create(
        category_id="acceptance_category",
        display_name="Stored category" if conflicting else "Acceptance",
        description="Stored category." if conflicting else "Disposable acceptance-test definitions.",
    )
    view = AuthzPermissionDefinition.objects.create(
        namespace="acceptance",
        name="view",
        display_name="Stored view" if conflicting else "View acceptance object",
        description="Stored view." if conflicting else "View the disposable object.",
        category=category,
        scopes=["course-v1"],
    )
    role = AuthzRoleDefinition.objects.create(
        role_id="acceptance_orphan" if orphan else ROLE,
        display_name="Stored role" if conflicting else "Acceptance editor",
        description="Stored role." if conflicting else "Disposable acceptance role.",
        scopes=["course-v1"],
    )
    if not orphan:
        edit = AuthzPermissionDefinition.objects.create(
            namespace="acceptance",
            name="edit",
            display_name="Stored edit" if conflicting else "Edit acceptance object",
            description="Stored edit." if conflicting else "Edit the disposable object.",
            category=category,
            scopes=["course-v1"],
        )
        AuthzRolePermission.objects.create(role=role, permission=view, scope="course-v1")
        AuthzRolePermission.objects.create(role=role, permission=edit, scope="course-v1")


def hold_role_lock():
    with transaction.atomic():
        AuthzRoleDefinition.objects.select_for_update().get(role_id=ROLE)
        print("acceptance role lock acquired", flush=True)
        time.sleep(8)


def assert_snapshot(expected):
    found = snapshot()
    role_ids = [row["role_id"] for row in found["roles"]]
    display_names = [row["display_name"] for row in found["roles"]]
    policy_actions = [row[2] for row in found["policies"] if row[0] == "p"]

    if expected == "base":
        assert role_ids == [ROLE], found
        assert found["permissions"] == ["edit", "view"], found
        assert policy_actions == ["act^acceptance.edit", "act^acceptance.view"], found
    elif expected == "metadata_changed":
        assert display_names == ["Acceptance editor renamed"], found
    elif expected == "permission_removed":
        assert found["permissions"] == ["view"], found
        assert policy_actions == ["act^acceptance.view"], found
    elif expected == "assigned_preserved":
        assert role_ids == [ROLE], found
        assert found["assignments"] == [(USER_SUBJECT, ROLE_SUBJECT, SCOPE)], found
        assert found["allows_view"] is True, found
    elif expected == "role_removed":
        assert role_ids == [], found
        assert found["assignments"] == [], found
        assert found["allows_view"] is False, found
    elif expected == "empty":
        assert role_ids == [] and found["permissions"] == [] and found["policies"] == [], found
    elif expected == "base_attributed":
        assert role_ids == [ROLE], found
        assert found["permissions"] == ["edit", "view"], found
        assert len(found["sources"]) >= 1, found
        assert policy_actions == ["act^acceptance.edit", "act^acceptance.view"], found
    elif expected == "base_without_orphan":
        assert role_ids == [ROLE], found
        assert "acceptance_orphan" not in role_ids, found
    elif expected == "unmanaged_preserved":
        assert found["unmanaged"], found
    elif expected == "extension_applied":
        assert display_names == ["Extended acceptance editor"], found
        assert policy_actions == ["act^acceptance.edit"], found
        assert len(found["sources"]) >= 1, found
    elif expected == "priority_extension_winner":
        assert display_names == ["High-priority editor"], found
        assert policy_actions == ["act^acceptance.view"], found
    elif expected == "multiple_scopes":
        scopes = [row[3] for row in found["policies"] if row[0] == "p"]
        assert scopes == ["course-v1^*", "lib^*"], found
    elif expected == "hidden_role":
        assert found["roles"] == [{"role_id": ROLE, "display_name": "Acceptance editor", "hidden": True}], found
    elif expected == "concurrent_updated":
        assert found["permissions"] == ["view"], found
        assert policy_actions == ["act^acceptance.view"], found
    else:
        raise AssertionError(f"unknown expectation: {expected}")
    print(json.dumps(found, indent=2, default=str))


action = os.environ["ACCEPTANCE_ACTION"]
if action == "clean":
    clean()
elif action == "assign":
    assign()
elif action == "seed_policy":
    seed_policy()
elif action == "seed_unmanaged":
    seed_unmanaged()
elif action == "seed_definitions":
    seed_definitions()
elif action == "seed_conflicting_definitions":
    seed_definitions(conflicting=True)
elif action == "seed_orphan_definition":
    seed_definitions(orphan=True)
elif action == "hold_role_lock":
    hold_role_lock()
elif action == "assert":
    assert_snapshot(os.environ["ACCEPTANCE_EXPECT"])
else:
    raise AssertionError(f"unknown action: {action}")
