from django.core.management.base import BaseCommand

from django.contrib.auth.models import User, Group
from openedx.core.djangoapps.content_libraries.models import (
    ContentLibrary,
    ContentLibraryPermission,
    ALL_RIGHTS_RESERVED,
)
from organizations.models import Organization

from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.api.users import (
    batch_unassign_role_from_users,
    get_user_role_assignments_in_scope,
)
from openedx_authz.constants.roles import LIBRARY_ADMIN, LIBRARY_USER


# Specify a unique prefix to avoid collisions with existing data
OBJECT_PREFIX = "tmlp_"

org_name = f"{OBJECT_PREFIX}org"
lib_name = f"{OBJECT_PREFIX}library"
group_name = f"{OBJECT_PREFIX}test_group"
user_names = [f"{OBJECT_PREFIX}user{i}" for i in range(3)]
group_user_names = [f"{OBJECT_PREFIX}guser{i}" for i in range(3)]
error_user_name = f"{OBJECT_PREFIX}error_user"
error_group_name = f"{OBJECT_PREFIX}error_group"
empty_group_name = f"{OBJECT_PREFIX}empty_group"


def setup_data():
    """
    Set up test data (run this **before** the migration).

    What this does:
    1. Creates an Organization and a ContentLibrary
    2. Creates Users and Groups
    3. Assigns legacy permissions using ContentLibraryPermission
    4. Creates invalid permissions for user and group (for error logging)
    """
    org = Organization.objects.create(name=org_name, short_name=org_name)
    library = ContentLibrary.objects.create(
        org=org,
        slug=lib_name,
        allow_public_learning=False,
        allow_public_read=False,
        license=ALL_RIGHTS_RESERVED,
    )

    # Create Users and Groups
    users = [
        User.objects.create_user(
            username=user_name,
            email=f"{user_name}@example.com",
        )
        for user_name in user_names
    ]

    group_users = [
        User.objects.create_user(
            username=user_name,
            email=f"{user_name}@example.com",
        )
        for user_name in group_user_names
    ]
    group = Group.objects.create(name=group_name)
    group.user_set.set(group_users)

    error_user = User.objects.create_user(
        username=error_user_name,
        email=f"{error_user_name}@example.com",
    )
    error_group = Group.objects.create(name=error_group_name)
    error_group.user_set.set([error_user])

    empty_group = Group.objects.create(name=empty_group_name)

    # Assign legacy permissions for users and group
    for user in users:
        ContentLibraryPermission.objects.create(
            user=user,
            library=library,
            access_level=ContentLibraryPermission.ADMIN_LEVEL,
        )

    ContentLibraryPermission.objects.create(
        group=group,
        library=library,
        access_level=ContentLibraryPermission.READ_LEVEL,
    )

    # Create invalid permissions for testing error logging
    ContentLibraryPermission.objects.create(
        user=error_user,
        library=library,
        access_level="invalid",
    )
    ContentLibraryPermission.objects.create(
        group=error_group,
        library=library,
        access_level="invalid",
    )

    # Edge case: empty group with no users
    ContentLibraryPermission.objects.create(
        group=empty_group,
        library=library,
        access_level=ContentLibraryPermission.READ_LEVEL,
    )


def verify_data():
    """
    Run this **after** the migration to verify that permissions were migrated correctly.

    Checks:
    1. Each individual user has the expected role in the new model.
    2. Each user from the group has the expected role in the new model.
    """
    AuthzEnforcer.get_enforcer().load_policy()

    scope_external_key = f"lib:{org_name}:{lib_name}"

    for user_name in user_names:
        assignments = get_user_role_assignments_in_scope(
            user_external_key=user_name,
            scope_external_key=scope_external_key,
        )
        assert len(assignments) == 1
        assert assignments[0].roles[0] == LIBRARY_ADMIN

    for group_user_name in group_user_names:
        assignments = get_user_role_assignments_in_scope(
            user_external_key=group_user_name,
            scope_external_key=scope_external_key,
        )
        assert len(assignments) == 1
        assert assignments[0].roles[0] == LIBRARY_USER

    print("Verification successful: all permissions were migrated correctly.")


def cleanup_data():
    """
    Clean up test data created for the migration test.
    Run this **after** verification (or when you want to reset the environment).
    """
    AuthzEnforcer.get_enforcer().load_policy()

    scope_external_key = f"lib:{org_name}:{lib_name}"

    batch_unassign_role_from_users(
        users=user_names,
        role_external_key=LIBRARY_ADMIN.external_key,
        scope_external_key=scope_external_key,
    )
    batch_unassign_role_from_users(
        users=group_user_names,
        role_external_key=LIBRARY_USER.external_key,
        scope_external_key=scope_external_key,
    )

    ContentLibrary.objects.filter(slug=lib_name).delete()
    Organization.objects.filter(name=org_name).delete()
    Group.objects.filter(name__in=[group_name, error_group_name, empty_group_name]).delete()

    for user_name in user_names + group_user_names + [error_user_name]:
        User.objects.filter(username=user_name).delete()

    print("Cleanup completed: test data removed.")


class Command(BaseCommand):
    """
    Utils for testing the Legacy Permission Migration.

    This command wraps the original shell utilities into an easy-to-use CLI.

    Usage:

        # 1. Before running the migration:
        python manage.py test_legacy_permission_migration setup

        # 2. Run the migration:
        python manage.py migrate openedx_authz 0002_migrate_legacy_permissions

        #   You should see something like:
        #   Migration completed with errors for 2 permissions.
        #   The following permissions could not be migrated:
        #   2025-11-05 22:04:30,870 ERROR ... Access level: invalid, Group: tmlp_error_group, Library: tmlp_library
        #   2025-11-05 22:04:30,870 ERROR ... Access level: invalid, User: tmlp_error_user, Library: tmlp_library

        # 3. After the migration:
        python manage.py test_legacy_permission_migration verify

        # 4. When finished:
        python manage.py test_legacy_permission_migration cleanup
    """

    help = "Test utilities for the legacy permission migration (setup, verify, cleanup)."

    def add_arguments(self, parser):
        parser.add_argument(
            "action",
            choices=["setup", "verify", "cleanup"],
            help="Which step to run: setup, verify, or cleanup.",
        )

    def handle(self, *args, **options):
        action = options["action"]

        if action == "setup":
            setup_data()
        elif action == "verify":
            verify_data()
        elif action == "cleanup":
            cleanup_data()
        else:
            self.stderr.write(self.style.ERROR(f"Unknown action: {action}"))
            return

        self.stdout.write(self.style.SUCCESS(f"Action '{action}' completed successfully."))
