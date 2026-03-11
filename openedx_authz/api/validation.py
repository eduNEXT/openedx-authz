"""Validation utilities for OpenedX AuthZ API.

This module provides validation functions for scope strings, particularly
for glob patterns used in role assignments.
"""

from openedx_authz.api.data import (
    EXTERNAL_KEY_SEPARATOR,
    GLOBAL_SCOPE_WILDCARD,
    ContentLibraryData,
    CourseOverviewData,
    ScopeData,
)


def validate_scope_with_glob(scope: ScopeData) -> None:
    """Validate that a scope with glob patterns follows rules.

    This function ensures that glob patterns (*) in scope strings are only
    allowed at the organization level and that the referenced organization
    exists to prevent overly broad or invalid permissions.

    Rules:
    - For course scopes: Must have exactly the format "course-v1:ORG*" where ORG exists
    - For library scopes: Must have exactly the format "lib:ORG*" where ORG exists
    - Wildcards must only appear at the end of the string
    - Wildcards are only allowed at organization level (not at course, run, or slug level)
    - Cannot have wildcards before the org identifier

    Args:
        scope (ScopeData): ScopeData instance to validate (e.g. ScopeData(external_key="course-v1:OpenedX*"))

    Examples:
        Valid scopes:
        - CourseOverviewData(external_key="course-v1:OpenedX*")  # org-level wildcard
        - ContentLibraryData(external_key="lib:DemoX*")  # org-level wildcard

        Invalid scopes:
        - course-v1* - wildcard before org
        - course-v1:* - wildcard without org prefix
        - course-v1:OpenedX+Course* - wildcard at course level (NOT allowed)
        - lib:DemoX:Slug* - wildcard at slug level (NOT allowed)
    """
    external_key = scope.external_key

    if GLOBAL_SCOPE_WILDCARD not in external_key:
        return None

    # Get the scope string without the trailing wildcard
    scope_prefix = external_key[: -len(GLOBAL_SCOPE_WILDCARD)]

    if isinstance(scope, CourseOverviewData):
        return _validate_course_scope_glob(scope_prefix)
    if isinstance(scope, ContentLibraryData):
        return _validate_library_scope_glob(scope_prefix)

    raise ValueError(f"Invalid scope: {scope}")


def _validate_org_identifier(scope_prefix: str) -> str:
    """Extract and structurally validate the organization identifier in a scope.

    This helper only validates the structure (namespace and org position). It does
    not check whether the organization actually exists. That is the responsibility
    of the scope-type specific validators.

    Args:
        scope_prefix (str): The scope without the trailing wildcard

    Returns:
        str: The extracted organization identifier

    Examples:
        >>> _validate_org_identifier("course-v1:OpenedX*")
        "OpenedX"
        >>> _validate_org_identifier("lib:DemoX*")
        "DemoX"
    """
    parts = scope_prefix.split(EXTERNAL_KEY_SEPARATOR)

    if len(parts) != 2 or parts[1] == "":
        raise ValueError("Scope glob must include exactly one organization identifier.")

    return parts[1]


def _course_org_exists(org: str) -> bool:
    """Check if there is at least one course with the given org.

    Args:
        org (str): Organization identifier extracted from the course scope

    Returns:
        bool: True if there is at least one CourseOverview whose org field matches
        the provided identifier in a case-sensitive way, False otherwise.
    """
    from openedx_authz.models.scopes import CourseOverview  # pylint: disable=import-outside-toplevel

    course_obj = CourseOverview.objects.filter(org=org).only("org").last()
    return course_obj is not None and course_obj.org == org


def _library_org_exists(org: str) -> bool:
    """Check if there is at least one content library with the given org.

    Args:
        org (str): Organization identifier extracted from the library scope

    Returns:
        bool: True if there is at least one ContentLibrary whose related
        organization's short_name matches the provided identifier in a
        case-sensitive way, False otherwise.
    """
    from openedx_authz.models.scopes import ContentLibrary  # pylint: disable=import-outside-toplevel

    lib_obj = ContentLibrary.objects.filter(org__short_name=org).only("org").last()
    return lib_obj is not None and lib_obj.org.short_name == org


def _validate_course_scope_glob(scope_prefix: str) -> None:
    """Validate a course scope with glob pattern.

    Course keys have format: course-v1:ORG+COURSE+RUN
    We only allow wildcards at the organization level (course-v1:ORG*).
    Wildcards at course or run level are not allowed.

    Args:
        scope_prefix (str): The course scope without the trailing wildcard
    """
    org = _validate_org_identifier(scope_prefix)

    if not _course_org_exists(org):
        raise ValueError(f"Organization '{org}' does not exist for any course.")


def _validate_library_scope_glob(scope_prefix: str) -> None:
    """Validate a library scope with glob pattern.

    Library keys have format: lib:ORG:SLUG
    We only allow wildcards at the organization level (lib:ORG*).
    Wildcards at slug level are not allowed.

    Args:
        scope_prefix (str): The library scope without the trailing wildcard
    """
    org = _validate_org_identifier(scope_prefix)

    if not _library_org_exists(org):
        raise ValueError(f"Organization '{org}' does not exist for any library.")
