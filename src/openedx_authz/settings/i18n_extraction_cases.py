"""
Test settings that add i18n extraction test schemas next to the real schema.

AUTHZ_I18N_CASES is a comma-separated list of directory names under
openedx_authz/tests/schema/i18n_extraction_cases/.
"""

import os

from openedx_authz.settings.test import *  # noqa: F403 pylint: disable=wildcard-import,unused-wildcard-import

OPENEDX_AUTHZ_SCHEMA_DIRECTORIES = [
    f"openedx_authz/tests/schema/i18n_extraction_cases/{case}"
    for case in os.environ.get("AUTHZ_I18N_CASES", "").split(",")
    if case
]
