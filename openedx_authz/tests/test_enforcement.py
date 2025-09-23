"""
Tests for Casbin enforcement using model.conf and authz.policy files.

This module contains comprehensive tests for the authorization enforcement
using Casbin with the configured model and policy files.
"""

import os
from typing import TypedDict
from unittest import TestCase

import casbin
from ddt import data, ddt, unpack


class AuthRequest(TypedDict):
    """
    Represents an authorization request with all necessary parameters.
    """

    subject: str
    action: str
    scope: str
    expected_result: bool


COMMON_ACTION_GROUPING = [
    # manage implies all other actions
    ["g2", "act:manage", "act:edit"],
    ["g2", "act:manage", "act:read"],
    ["g2", "act:manage", "act:write"],
    ["g2", "act:manage", "act:delete"],
    # edit implies read and write
    ["g2", "act:edit", "act:read"],
    ["g2", "act:edit", "act:write"],
    ["g2", "act:edit", "act:read"],
    ["g2", "act:edit", "act:write"],
]


@ddt
class CasbinEnforcementTestCase(TestCase):
    """
    Test case for Casbin enforcement policies.

    This test class loads the model.conf and authz.policy files and runs
    enforcement tests for different user roles and permissions.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the Casbin enforcer with model and policy files."""
        super().setUpClass()

        engine_config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "engine", "config")
        model_file = os.path.join(engine_config_dir, "model.conf")

        if not os.path.isfile(model_file):
            raise FileNotFoundError(f"Model file not found: {model_file}")

        cls.enforcer = casbin.Enforcer(model_file)

    def _load_policy(self, policy: list[str] = None) -> None:
        """Load policy into the enforcer."""
        self.enforcer.clear_policy()
        for rule in policy or []:
            if rule[0] == "p":
                self.enforcer.add_named_policy("p", rule[1:])
            elif rule[0] == "g":
                self.enforcer.add_named_grouping_policy("g", rule[1:])
            elif rule[0] == "g2":
                self.enforcer.add_named_grouping_policy("g2", rule[1:])
            else:
                raise ValueError(f"Invalid policy rule: {rule}")

    def _test_enforcement(self, policy: list[str] = None, request: AuthRequest = None) -> None:
        """
        Helper method to test enforcement and provide detailed feedback.

        Args:
            policy (list[str]): A list of policy rules to load into the enforcer
            request (AuthRequest): An authorization request containing all necessary parameters
        """
        self._load_policy(policy)
        subject, action, scope = request["subject"], request["action"], request["scope"]
        result = self.enforcer.enforce(subject, action, scope)
        error_msg = f"Request: {subject} {action} {scope}"
        self.assertEqual(result, request["expected_result"], error_msg)


@ddt
class SystemWideRoleTests(CasbinEnforcementTestCase):
    """Tests for system-wide roles with global access permissions."""

    POLICY = [
        ["p", "role:platform_admin", "act:manage", "*", "allow"],
        ["g", "user:user-1", "role:platform_admin"],
    ] + COMMON_ACTION_GROUPING

    GENERAL_CASES = [
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "course-v1:any-org+any-course+any-course-run",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "lib:any-library",
            "expected_result": True,
        },
    ]

    @data(*GENERAL_CASES)
    def test_platform_admin_general_access(self, request: AuthRequest):
        """Test that platform administrators have full access to all resources."""
        self._test_enforcement(self.POLICY, request)


@ddt
class ActionGroupingTests(CasbinEnforcementTestCase):
    """Tests for action grouping."""

    POLICY = [
        ["p", "role:role-1", "act:manage", "org:any-org", "allow"],
        ["g", "user:user-1", "role:role-1"],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": "user:user-1",
            "action": "act:edit",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:read",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:write",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:delete",
            "scope": "org:any-org",
            "expected_result": True,
        },
    ]

    @data(*CASES)
    def test_action_grouping_access(self, request: AuthRequest):
        """Test that users have access through action grouping."""
        self._test_enforcement(self.POLICY, request)


@ddt
class RoleAssignmentTests(CasbinEnforcementTestCase):
    """Tests for role assignment."""

    POLICY = [
        # Policies
        ["p", "role:platform_admin", "act:manage", "*", "allow"],
        ["p", "role:org_admin", "act:manage", "org:any-org", "allow"],
        ["p", "role:org_editor", "act:edit", "org:any-org", "allow"],
        ["p", "role:org_author", "act:write", "org:any-org", "allow"],
        ["p", "role:course_admin", "act:manage", "course-v1:any-org+any-course+any-course-run", "allow"],
        ["p", "role:library_admin", "act:manage", "lib:any-library", "allow"],
        ["p", "role:library_editor", "act:edit", "lib:any-library", "allow"],
        ["p", "role:library_reviewer", "act:read", "lib:any-library", "allow"],
        ["p", "role:library_author", "act:write", "lib:any-library", "allow"],
        # Role assignments
        ["g", "user:user-1", "role:platform_admin"],
        ["g", "user:user-2", "role:org_admin"],
        ["g", "user:user-3", "role:org_editor"],
        ["g", "user:user-4", "role:org_author"],
        ["g", "user:user-5", "role:course_admin"],
        ["g", "user:user-6", "role:library_admin"],
        ["g", "user:user-7", "role:library_editor"],
        ["g", "user:user-8", "role:library_reviewer"],
        ["g", "user:user-9", "role:library_author"],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-2",
            "action": "act:manage",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-3",
            "action": "act:edit",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-4",
            "action": "act:write",
            "scope": "org:any-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-5",
            "action": "act:manage",
            "scope": "course-v1:any-org+any-course+any-course-run",
            "expected_result": True,
        },
        {
            "subject": "user:user-6",
            "action": "act:manage",
            "scope": "lib:any-library",
            "expected_result": True,
        },
        {
            "subject": "user:user-7",
            "action": "act:edit",
            "scope": "lib:any-library",
            "expected_result": True,
        },
        {
            "subject": "user:user-8",
            "action": "act:read",
            "scope": "lib:any-library",
            "expected_result": True,
        },
        {
            "subject": "user:user-9",
            "action": "act:write",
            "scope": "lib:any-library",
            "expected_result": True,
        },
    ]

    @data(*CASES)
    def test_role_assignment_access(self, request: AuthRequest):
        """Test that users have access through role assignment."""
        self._test_enforcement(self.POLICY, request)


@ddt
class DeniedAccessTests(CasbinEnforcementTestCase):
    """Tests for denied access."""

    POLICY = [
        ["p", "role:platform_admin", "act:manage", "*", "allow"],
        ["p", "role:platform_admin", "act:manage", "org:restricted-org", "deny"],
        ["g", "user:user-1", "role:platform_admin"],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "org:allowed-org",
            "expected_result": True,
        },
        {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": "org:restricted-org",
            "expected_result": False,
        },
        {
            "subject": "user:user-1",
            "action": "act:edit",
            "scope": "org:restricted-org",
            "expected_result": False,
        },
        {
            "subject": "user:user-1",
            "action": "act:read",
            "scope": "org:restricted-org",
            "expected_result": False,
        },
        {
            "subject": "user:user-1",
            "action": "act:write",
            "scope": "org:restricted-org",
            "expected_result": False,
        },
        {
            "subject": "user:user-1",
            "action": "act:delete",
            "scope": "org:restricted-org",
            "expected_result": False,
        },
    ]

    @data(*CASES)
    def test_denied_access(self, request: AuthRequest):
        """Test that users have denied access."""
        self._test_enforcement(self.POLICY, request)


@ddt
class WildcardScopeTests(CasbinEnforcementTestCase):
    """Tests for wildcard scope."""

    POLICY = [
        # Policies
        ["p", "role:platform_admin", "act:manage", "*", "allow"],
        ["p", "role:org_admin", "act:manage", "org:*", "allow"],
        ["p", "role:course_admin", "act:manage", "course-v1:*", "allow"],
        ["p", "role:library_admin", "act:manage", "lib:*", "allow"],
        # Role assignments
        ["g", "user:user-1", "role:platform_admin"],
        ["g", "user:user-2", "role:org_admin"],
        ["g", "user:user-3", "role:course_admin"],
        ["g", "user:user-4", "role:library_admin"],
    ] + COMMON_ACTION_GROUPING

    @data(
        ("*", True),
        ("org:MIT", True),
        ("course-v1:OpenedX+DemoX+CS101", True),
        ("lib:math-basics", True),
    )
    @unpack
    def test_wildcard_global_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard global scope."""
        request = {
            "subject": "user:user-1",
            "action": "act:manage",
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        ("org:MIT", True),
        ("course-v1:OpenedX+DemoX+CS101", False),
        ("lib:math-basics", False),
    )
    @unpack
    def test_wildcard_org_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard org scope."""
        request = {
            "subject": "user:user-2",
            "action": "act:manage",
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        ("org:MIT", False),
        ("course-v1:OpenedX+DemoX+CS101", True),
        ("lib:math-basics", False),
    )
    @unpack
    def test_wildcard_course_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard course scope."""
        request = {
            "subject": "user:user-3",
            "action": "act:manage",
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        ("org:MIT", False),
        ("course-v1:OpenedX+DemoX+CS101", False),
        ("lib:math-basics", True),
    )
    @unpack
    def test_wildcard_library_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard library scope."""
        request = {
            "subject": "user:user-4",
            "action": "act:manage",
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)
