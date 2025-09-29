"""
Django management command for loading Casbin policies from a file into the database.

This command loads policy rules from a CSV-formatted policy file (like authz.policy)
and stores them in the database using the custom enforcer's ExtendedAdapter.

The command supports:
- Loading policies from CSV files with proper format validation
- Clearing existing policies before loading (optional)
- Dry-run mode to preview what would be loaded
- Detailed logging of loaded policies and statistics

Example usage:
    python manage.py load_policy --policy-file authz.policy

    python manage.py load_policy --policy-file authz.policy --clear-existing

    python manage.py load_policy --policy-file authz.policy --dry-run
"""

import os
from argparse import ArgumentParser
from typing import List, Tuple

from django.core.management.base import BaseCommand, CommandError

from openedx_authz.engine.enforcer import enforcer


class Command(BaseCommand):
    """
    Django management command for loading Casbin policies from a file.

    This command reads policy rules from a CSV-formatted file and stores them
    in the database using the custom enforcer's ExtendedAdapter. It supports
    various policy types including permissions (p), role assignments (g), and
    action inheritance (g2).
    """

    help = (
        "Load Casbin policies from a CSV file into the database. "
        "Supports policy rules (p), role assignments (g), and action inheritance (g2). "
        "Use --policy-file to specify the policy file path. "
        "Use --clear-existing to remove existing policies before loading. "
        "Use --dry-run to preview what would be loaded without making changes."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        """Add command-line arguments to the argument parser."""
        parser.add_argument(
            "--policy-file",
            type=str,
            required=True,
            help="Path to the Casbin policy file (CSV format with policies, roles, and action grouping)",
        )
        parser.add_argument(
            "--clear-existing",
            action="store_true",
            help="Clear all existing policies from the database before loading new ones",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be loaded without making any database changes",
        )

    def handle(self, *args, **options) -> None:
        """Execute the policy loading command."""
        policy_file_path = options["policy_file"]
        clear_existing = options["clear_existing"]
        dry_run = options["dry_run"]

        if not os.path.isfile(policy_file_path):
            raise CommandError(f"Policy file not found: {policy_file_path}")

        self.stdout.write(self.style.SUCCESS("Casbin Policy Loader"))
        self.stdout.write(f"Policy file: {policy_file_path}")
        self.stdout.write(f"Clear existing: {clear_existing}")
        self.stdout.write(f"Dry run: {dry_run}")
        self.stdout.write("")

        try:
            policies = self._parse_policy_file(policy_file_path)

            if not policies:
                self.stdout.write(self.style.WARNING("No valid policies found in the file"))
                return

            self._display_statistics(policies)

            if dry_run:
                self._display_dry_run(policies)
                return

            self._load_policies_to_database(policies, clear_existing)

            enforcer.load_policy()
            self.stdout.write(self.style.SUCCESS("✓ Enforcer policies reloaded"))

        except Exception as e:
            raise CommandError(f"Error loading policies: {str(e)}") from e

    def _parse_policy_file(self, file_path: str) -> List[Tuple[str, ...]]:
        """
        Parse the policy file and extract valid policy rules.

        Args:
            file_path (str): Path to the policy file

        Returns:
            List[Tuple[str, ...]]: List of tuples representing policy rules
        """
        policies = []

        with open(file_path, "r", encoding="utf-8") as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    parts = [part.strip() for part in line.split(",")]

                    if len(parts) < 2:
                        self.stdout.write(self.style.WARNING(f"Skipping invalid line {line_num}: {line}"))
                        continue

                    ptype = parts[0]
                    if ptype not in ["p", "g", "g2"]:
                        self.stdout.write(
                            self.style.WARNING(f"Skipping unknown policy type '{ptype}' on line {line_num}")
                        )
                        continue

                    policies.append(tuple(parts))

                except Exception as e:  # pylint: disable=broad-exception-caught
                    self.stdout.write(self.style.WARNING(f"Error parsing line {line_num}: {line} - {str(e)}"))
                    continue

        return policies

    def _display_statistics(self, policies: List[Tuple[str, ...]]) -> None:
        """Display statistics about the parsed policies."""
        p_policies = [p for p in policies if p[0] == "p"]
        g_policies = [p for p in policies if p[0] == "g"]
        g2_policies = [p for p in policies if p[0] == "g2"]

        self.stdout.write(f"✓ Parsed {len(policies)} total policies:")
        self.stdout.write(f"  - {len(p_policies)} permission policies (p)")
        self.stdout.write(f"  - {len(g_policies)} role assignments (g)")
        self.stdout.write(f"  - {len(g2_policies)} action inheritance rules (g2)")
        self.stdout.write("")

    def _display_dry_run(self, policies: List[Tuple[str, ...]]) -> None:
        """Display a preview of what would be loaded in dry-run mode."""
        self.stdout.write(self.style.SUCCESS("DRY RUN - Preview of policies to be loaded:"))
        self.stdout.write("")

        for i, policy in enumerate(policies, 1):
            self.stdout.write(f"{i:2d}. {', '.join(policy)}")

        self.stdout.write("")
        self.stdout.write(self.style.WARNING("No changes were made to the database"))

    def _load_policies_to_database(self, policies: List[Tuple[str, ...]], clear_existing: bool) -> None:
        """
        Load policies into the database using Casbin enforcer methods.

        Args:
            policies (List[Tuple[str, ...]]): List of policy tuples to load
            clear_existing (bool): Whether to clear existing policies first
        """
        if clear_existing:
            enforcer.clear_policy()
            self.stdout.write("✓ Cleared all existing policies")

        loaded_count = 0
        for policy_tuple in policies:
            ptype = policy_tuple[0]
            policy_params = list(policy_tuple[1:])

            try:
                if ptype == "p":
                    if len(policy_params) >= 4:
                        enforcer.add_policy(*policy_params)
                        loaded_count += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(f"Skipping incomplete permission policy: {', '.join(policy_tuple)}")
                        )
                elif ptype == "g":
                    if len(policy_params) >= 2:
                        enforcer.add_named_grouping_policy("g", policy_params)
                        loaded_count += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(f"Skipping incomplete role assignment policy: {', '.join(policy_tuple)}")
                        )
                elif ptype == "g2":
                    if len(policy_params) >= 2:
                        enforcer.add_named_grouping_policy("g2", policy_params)
                        loaded_count += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f"Skipping incomplete action inheritance policy: {', '.join(policy_tuple)}"
                            )
                        )
            except Exception as e:  # pylint: disable=broad-exception-caught
                self.stdout.write(self.style.ERROR(f"Failed to add policy {', '.join(policy_tuple)}: {str(e)}"))

        self.stdout.write(self.style.SUCCESS(f"✓ Loaded {loaded_count} policies using Casbin enforcer methods"))
