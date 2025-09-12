"""
Simple tests for enforcer.enforce()
"""

from casbin_adapter.enforcer import enforcer

from casbin_adapter.models import CasbinRule


def setup_test_data():
    """Setup the test data."""
    CasbinRule.objects.all().delete()

    # Policies (p)
    enforcer.add_policy("role:platform_admin", "act:manage", "*", "allow")
    enforcer.add_policy("role:org_admin", "act:manage", "lib:*", "allow")
    enforcer.add_policy("role:org_editor", "act:edit", "lib:*", "allow")
    enforcer.add_policy("role:library_author", "act:edit", "lib:*", "allow")
    enforcer.add_policy("role:library_reviewer", "act:read", "lib:*", "allow")
    enforcer.add_policy("role:org_editor", "act:edit", "lib:restricted-content", "deny")

    # Grouping Policy (g)
    enforcer.add_named_grouping_policy("g", ["user:admin", "role:platform_admin", "*"])
    enforcer.add_named_grouping_policy("g", ["user:alice", "role:org_admin", "org:OpenedX"])
    enforcer.add_named_grouping_policy("g", ["user:bob", "role:org_editor", "org:MIT"])
    enforcer.add_named_grouping_policy("g", ["user:mary", "role:library_author", "lib:math-basics"])
    enforcer.add_named_grouping_policy("g", ["user:john", "role:library_author", "lib:science-101"])
    enforcer.add_named_grouping_policy("g", ["user:sarah", "role:library_reviewer", "lib:math-basics"])

    # Grouping Policy (g2)
    enforcer.add_named_grouping_policy("g2", ["act:manage", "act:read"])
    enforcer.add_named_grouping_policy("g2", ["act:manage", "act:write"])
    enforcer.add_named_grouping_policy("g2", ["act:manage", "act:delete"])
    enforcer.add_named_grouping_policy("g2", ["act:edit", "act:read"])
    enforcer.add_named_grouping_policy("g2", ["act:edit", "act:write"])


def run_tests():
    """Run the tests."""
    enforcer.load_policy()

    # ===== ADMIN GLOBAL (user:admin) =====
    # Should return True for everything
    enforcer.enforce("user:admin", "act:manage", "lib:math-basics", "*")  # True
    enforcer.enforce("user:admin", "act:delete", "lib:science-101", "*")  # True
    enforcer.enforce("user:admin", "act:read", "org:OpenedX", "*")  # True

    # ===== ORG ADMIN (user:alice in org:OpenedX) =====
    # Can manage libraries in their organization
    enforcer.enforce("user:alice", "act:manage", "lib:openedx-library", "org:OpenedX")  # True
    enforcer.enforce("user:alice", "act:delete", "lib:openedx-content", "org:OpenedX")  # True
    enforcer.enforce("user:alice", "act:write", "lib:math-basics", "org:OpenedX")  # True (manage implies write)

    # CANNOT manage libraries in other organizations
    enforcer.enforce("user:alice", "act:manage", "lib:mit-library", "org:MIT")  # False
    enforcer.enforce("user:alice", "act:read", "lib:mit-content", "org:MIT")  # False

    # ===== ORG EDITOR (user:bob in org:MIT) =====

    # NOTE: All enforcements with bob are returning false because of the negative rule (?)

    # Can edit in their organization
    enforcer.enforce("user:bob", "act:edit", "lib:mit-course", "org:MIT")  # True [fails]
    enforcer.enforce("user:bob", "act:read", "lib:mit-content", "org:MIT")  # True (edit implies read) [fails]
    enforcer.enforce("user:bob", "act:write", "lib:mit-data", "org:MIT")  # True (edit implies write) [fails]

    # CANNOT delete (edit does not include delete)
    enforcer.enforce("user:bob", "act:delete", "lib:mit-course", "org:MIT")  # False
    enforcer.enforce("user:bob", "act:manage", "lib:mit-course", "org:MIT")  # False

    # Blocked by negative rule
    enforcer.enforce("user:bob", "act:edit", "lib:restricted-content", "org:MIT")  # False (deny rule)
    enforcer.enforce("user:bob", "act:read", "lib:restricted-content", "org:MIT")  # False (deny rule)

    # ===== LIBRARY AUTHOR (user:mary for lib:math-basics) =====
    # Can edit their specific library
    enforcer.enforce("user:mary", "act:edit", "lib:math-basics", "lib:math-basics")  # True
    enforcer.enforce("user:mary", "act:read", "lib:math-basics", "lib:math-basics")  # True (edit implies read)
    enforcer.enforce("user:mary", "act:write", "lib:math-basics", "lib:math-basics")  # True (edit implies write)

    # CANNOT delete (edit does not include delete)
    enforcer.enforce("user:mary", "act:delete", "lib:math-basics", "lib:math-basics")  # False [fails]
    enforcer.enforce("user:mary", "act:manage", "lib:math-basics", "lib:math-basics")  # False [fails]

    # CANNOT access other libraries
    enforcer.enforce("user:mary", "act:edit", "lib:science-101", "lib:science-101")  # False
    enforcer.enforce("user:mary", "act:read", "lib:science-101", "lib:math-basics")  # False (incorrect scope) [fails]

    # ===== LIBRARY REVIEWER (user:sarah for lib:math-basics) =====
    # Only read
    enforcer.enforce("user:sarah", "act:read", "lib:math-basics", "lib:math-basics")  # True

    # CANNOT write/edit/delete
    enforcer.enforce("user:sarah", "act:write", "lib:math-basics", "lib:math-basics")  # False [fails]
    enforcer.enforce("user:sarah", "act:edit", "lib:math-basics", "lib:math-basics")  # False [fails]
    enforcer.enforce("user:sarah", "act:delete", "lib:math-basics", "lib:math-basics")  # False [fails]

    # ===== USERS WITHOUT ROLES =====
    # No access
    enforcer.enforce("user:unknown", "act:read", "lib:math-basics", "lib:math-basics")  # False
    enforcer.enforce("user:mary", "act:read", "lib:science-101", "lib:science-101")  # False

    # ===== INCORRECT SCOPES =====
    # Same user, but incorrect scope
    enforcer.enforce("user:alice", "act:manage", "lib:openedx-lib", "*")  # False (Alice no es admin global)
    enforcer.enforce("user:mary", "act:edit", "lib:math-basics", "org:OpenedX")  # False (Mary needs scope lib:)
    enforcer.enforce("user:bob", "act:edit", "lib:mit-course", "lib:mit-course")  # False (Bob needs scope org:)

    # ===== ACTION INHERITANCE =====
    # manage implies read, write, delete
    enforcer.enforce("user:alice", "act:read", "lib:openedx-test", "org:OpenedX")  # True (manage → read)
    enforcer.enforce("user:alice", "act:write", "lib:openedx-test", "org:OpenedX")  # True (manage → write)
    enforcer.enforce("user:alice", "act:delete", "lib:openedx-test", "org:OpenedX")  # True (manage → delete)

    # edit implies read, write (NO delete)
    enforcer.enforce("user:bob", "act:read", "lib:mit-test", "org:MIT")  # True (edit → read) [fails]
    enforcer.enforce("user:bob", "act:write", "lib:mit-test", "org:MIT")  # True (edit → write) [fails]
    enforcer.enforce("user:bob", "act:delete", "lib:mit-test", "org:MIT")  # False (edit ↛ delete) [fails]
