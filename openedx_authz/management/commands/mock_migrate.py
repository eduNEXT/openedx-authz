import logging

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


logger = logging.getLogger(__name__)


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
    logger.info("AUTHZ-INIT: " + "=" * 80)
    logger.info("AUTHZ-INIT: SETUP - Starting test data creation")
    logger.info("AUTHZ-INIT: " + "=" * 80)

    logger.info(f"AUTHZ-INIT: Creating organization: {org_name}")
    org = Organization.objects.create(name=org_name, short_name=org_name)
    logger.info(f"AUTHZ-INIT: ✓ Organization created with ID: {org.id}")

    logger.info(f"AUTHZ-INIT: Creating content library: {lib_name} under org: {org_name}")
    library = ContentLibrary.objects.create(
        org=org,
        slug=lib_name,
        allow_public_learning=False,
        allow_public_read=False,
        license=ALL_RIGHTS_RESERVED,
    )
    logger.info(f"AUTHZ-INIT: ✓ ContentLibrary created with ID: {library.id}, slug: {library.slug}")

    logger.info(f"AUTHZ-INIT: Creating {len(user_names)} individual users: {user_names}")
    users = [
        User.objects.create_user(
            username=user_name,
            email=f"{user_name}@example.com",
        )
        for user_name in user_names
    ]
    logger.info(f"AUTHZ-INIT: ✓ Created {len(users)} individual users")

    logger.info(f"AUTHZ-INIT: Creating {len(group_user_names)} group users: {group_user_names}")
    group_users = [
        User.objects.create_user(
            username=user_name,
            email=f"{user_name}@example.com",
        )
        for user_name in group_user_names
    ]
    logger.info(f"AUTHZ-INIT: ✓ Created {len(group_users)} group users")

    logger.info(f"AUTHZ-INIT: Creating group: {group_name} with {len(group_users)} members")
    group = Group.objects.create(name=group_name)
    group.user_set.set(group_users)
    logger.info(f"AUTHZ-INIT: ✓ Group created with ID: {group.id}, members: {[u.username for u in group.user_set.all()]}")

    logger.info(f"AUTHZ-INIT: Creating error test user: {error_user_name}")
    error_user = User.objects.create_user(
        username=error_user_name,
        email=f"{error_user_name}@example.com",
    )
    logger.info(f"AUTHZ-INIT: ✓ Error test user created with ID: {error_user.id}")

    logger.info(f"AUTHZ-INIT: Creating error test group: {error_group_name}")
    error_group = Group.objects.create(name=error_group_name)
    error_group.user_set.set([error_user])
    logger.info(f"AUTHZ-INIT: ✓ Error test group created with ID: {error_group.id}")

    logger.info(f"AUTHZ-INIT: Creating empty group: {empty_group_name}")
    empty_group = Group.objects.create(name=empty_group_name)
    logger.info(f"AUTHZ-INIT: ✓ Empty group created with ID: {empty_group.id}, members: {empty_group.user_set.count()}")

    logger.info(f"AUTHZ-INIT: Assigning ADMIN_LEVEL permissions to {len(users)} individual users")
    for user in users:
        perm = ContentLibraryPermission.objects.create(
            user=user,
            library=library,
            access_level=ContentLibraryPermission.ADMIN_LEVEL,
        )
        logger.info(f"AUTHZ-INIT:   ✓ Created permission ID {perm.id}: user={user.username}, level={perm.access_level}")

    logger.info(f"AUTHZ-INIT: Assigning READ_LEVEL permission to group: {group_name}")
    group_perm = ContentLibraryPermission.objects.create(
        group=group,
        library=library,
        access_level=ContentLibraryPermission.READ_LEVEL,
    )
    logger.info(f"AUTHZ-INIT:   ✓ Created permission ID {group_perm.id}: group={group.name}, level={group_perm.access_level}")

    logger.info("AUTHZ-INIT: Creating INVALID permissions for error testing")
    error_user_perm = ContentLibraryPermission.objects.create(
        user=error_user,
        library=library,
        access_level="invalid",
    )
    logger.info(f"AUTHZ-INIT:   ✓ Created invalid permission ID {error_user_perm.id}: user={error_user.username}, level='invalid'")

    error_group_perm = ContentLibraryPermission.objects.create(
        group=error_group,
        library=library,
        access_level="invalid",
    )
    logger.info(f"AUTHZ-INIT:   ✓ Created invalid permission ID {error_group_perm.id}: group={error_group.name}, level='invalid'")

    logger.info("AUTHZ-INIT: Creating READ_LEVEL permission for empty group (edge case)")
    empty_group_perm = ContentLibraryPermission.objects.create(
        group=empty_group,
        library=library,
        access_level=ContentLibraryPermission.READ_LEVEL,
    )
    logger.info(f"AUTHZ-INIT:   ✓ Created permission ID {empty_group_perm.id}: group={empty_group.name}, level={empty_group_perm.access_level}")

    total_perms = ContentLibraryPermission.objects.filter(library=library).count()
    logger.info("AUTHZ-INIT: " + "=" * 80)
    logger.info(f"AUTHZ-INIT: SETUP COMPLETE - Created {total_perms} total permissions for library '{lib_name}'")
    logger.info("AUTHZ-INIT: " + "=" * 80)


def verify_data():
    """
    Run this **after** the migration to verify that permissions were migrated correctly.

    Checks:
    1. Each individual user has the expected role in the new model.
    2. Each user from the group has the expected role in the new model.
    """
    logger.info("AUTHZ-INIT: " + "=" * 80)
    logger.info("AUTHZ-INIT: VERIFY - Starting verification of migrated permissions")
    logger.info("AUTHZ-INIT: " + "=" * 80)

    logger.info("AUTHZ-INIT: Loading authorization policies from enforcer")
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    logger.info(f"AUTHZ-INIT: ✓ Enforcer loaded, total policies: {len(enforcer.get_policy())}")

    scope_external_key = f"lib:{org_name}:{lib_name}"
    logger.info(f"AUTHZ-INIT: Checking permissions for scope: {scope_external_key}")

    logger.info("")
    logger.info(f"AUTHZ-INIT: Verifying {len(user_names)} individual users (expected role: {LIBRARY_ADMIN}):")
    all_passed = True

    for user_name in user_names:
        logger.info(f"AUTHZ-INIT:   Checking user: {user_name}")
        try:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user_name,
                scope_external_key=scope_external_key,
            )
            logger.info(f"AUTHZ-INIT:     Found {len(assignments)} assignment(s)")

            if len(assignments) != 1:
                logger.error(f"AUTHZ-INIT:     ✗ FAILED: Expected 1 assignment, got {len(assignments)}")
                logger.error(f"AUTHZ-INIT:       Assignments: {assignments}")
                all_passed = False
                continue

            actual_role = assignments[0].roles[0]
            if actual_role != LIBRARY_ADMIN:
                logger.error(f"AUTHZ-INIT:     ✗ FAILED: Expected role {LIBRARY_ADMIN}, got {actual_role}")
                logger.error(f"AUTHZ-INIT:       Full assignment: {assignments[0]}")
                all_passed = False
                continue

            logger.info(f"AUTHZ-INIT:     ✓ PASSED: User has {actual_role} role")

        except Exception as e:
            logger.error(f"AUTHZ-INIT:     ✗ EXCEPTION while checking {user_name}: {e}", exc_info=True)
            all_passed = False

    logger.info("")
    logger.info(f"AUTHZ-INIT: Verifying {len(group_user_names)} group users (expected role: {LIBRARY_USER}):")

    for group_user_name in group_user_names:
        logger.info(f"AUTHZ-INIT:   Checking group user: {group_user_name}")
        try:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=group_user_name,
                scope_external_key=scope_external_key,
            )
            logger.info(f"AUTHZ-INIT:     Found {len(assignments)} assignment(s)")

            if len(assignments) != 1:
                logger.error(f"AUTHZ-INIT:     ✗ FAILED: Expected 1 assignment, got {len(assignments)}")
                logger.error(f"AUTHZ-INIT:       Assignments: {assignments}")
                all_passed = False
                continue

            actual_role = assignments[0].roles[0]
            if actual_role != LIBRARY_USER:
                logger.error(f"AUTHZ-INIT:     ✗ FAILED: Expected role {LIBRARY_USER}, got {actual_role}")
                logger.error(f"AUTHZ-INIT:       Full assignment: {assignments[0]}")
                all_passed = False
                continue

            logger.info(f"AUTHZ-INIT:     ✓ PASSED: User has {actual_role} role")

        except Exception as e:
            logger.error(f"AUTHZ-INIT:     ✗ EXCEPTION while checking {group_user_name}: {e}", exc_info=True)
            all_passed = False

    logger.info("")
    logger.info("AUTHZ-INIT: " + "=" * 80)
    if all_passed:
        logger.info("AUTHZ-INIT: VERIFICATION SUCCESSFUL - All permissions migrated correctly!")
        print("Verification successful: all permissions were migrated correctly.")
    else:
        logger.error("AUTHZ-INIT: VERIFICATION FAILED - Some checks did not pass. See errors above.")
        raise AssertionError("Verification failed - see logs for details")
    logger.info("AUTHZ-INIT: " + "=" * 80)


def cleanup_data():
    """
    Clean up test data created for the migration test.
    Run this **after** verification (or when you want to reset the environment).
    """
    logger.info("AUTHZ-INIT: " + "=" * 80)
    logger.info("AUTHZ-INIT: CLEANUP - Starting cleanup of test data")
    logger.info("AUTHZ-INIT: " + "=" * 80)

    logger.info("AUTHZ-INIT: Loading authorization policies from enforcer")
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    logger.info("AUTHZ-INIT: ✓ Enforcer loaded")

    scope_external_key = f"lib:{org_name}:{lib_name}"
    logger.info(f"AUTHZ-INIT: Cleaning up role assignments for scope: {scope_external_key}")

    logger.info(f"AUTHZ-INIT: Removing {LIBRARY_ADMIN} role from {len(user_names)} users")
    try:
        batch_unassign_role_from_users(
            users=user_names,
            role_external_key=LIBRARY_ADMIN.external_key,
            scope_external_key=scope_external_key,
        )
        logger.info(f"AUTHZ-INIT:   ✓ Removed {LIBRARY_ADMIN} from individual users")
    except Exception as e:
        logger.error(f"AUTHZ-INIT:   ✗ Error removing {LIBRARY_ADMIN}: {e}", exc_info=True)

    logger.info(f"AUTHZ-INIT: Removing {LIBRARY_USER} role from {len(group_user_names)} group users")
    try:
        batch_unassign_role_from_users(
            users=group_user_names,
            role_external_key=LIBRARY_USER.external_key,
            scope_external_key=scope_external_key,
        )
        logger.info(f"AUTHZ-INIT:   ✓ Removed {LIBRARY_USER} from group users")
    except Exception as e:
        logger.error(f"AUTHZ-INIT:   ✗ Error removing {LIBRARY_USER}: {e}", exc_info=True)

    logger.info(f"AUTHZ-INIT: Deleting ContentLibrary: {lib_name}")
    lib_count = ContentLibrary.objects.filter(slug=lib_name).count()
    ContentLibrary.objects.filter(slug=lib_name).delete()
    logger.info(f"AUTHZ-INIT:   ✓ Deleted {lib_count} ContentLibrary object(s)")

    logger.info(f"AUTHZ-INIT: Deleting Organization: {org_name}")
    org_count = Organization.objects.filter(name=org_name).count()
    Organization.objects.filter(name=org_name).delete()
    logger.info(f"AUTHZ-INIT:   ✓ Deleted {org_count} Organization object(s)")

    logger.info(f"AUTHZ-INIT: Deleting Groups: {group_name}, {error_group_name}, {empty_group_name}")
    group_count = Group.objects.filter(name__in=[group_name, error_group_name, empty_group_name]).count()
    Group.objects.filter(name__in=[group_name, error_group_name, empty_group_name]).delete()
    logger.info(f"AUTHZ-INIT:   ✓ Deleted {group_count} Group object(s)")

    all_users = user_names + group_user_names + [error_user_name]
    logger.info(f"AUTHZ-INIT: Deleting {len(all_users)} Users")
    for user_name in all_users:
        user_count = User.objects.filter(username=user_name).count()
        if user_count > 0:
            User.objects.filter(username=user_name).delete()
            logger.info(f"AUTHZ-INIT:   ✓ Deleted user: {user_name}")
        else:
            logger.warning(f"AUTHZ-INIT:   ! User not found: {user_name}")

    logger.info("AUTHZ-INIT: " + "=" * 80)
    logger.info("AUTHZ-INIT: CLEANUP COMPLETE - Test data removed")
    logger.info("AUTHZ-INIT: " + "=" * 80)
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
