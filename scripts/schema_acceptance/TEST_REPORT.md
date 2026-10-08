# Authorization schema acceptance test report

| Field | Value |
| --- | --- |
| Target | `rod/authz-schema-loader` at `7a03353` |
| Environment | Disposable Tutor 21.0.3 development environment |
| Scope | Real `load_authz_schema` command with stored definitions, Casbin policies, assignments, and enforcement checks |
| Result | **25 passed, 2 failed** |

## Results

| Area | Case | Scenario | Result |
| --- | --- | --- | --- |
| Lifecycle | `initial_apply` | Apply a schema to an empty system. | Pass |
| Lifecycle | `dry_run` | Report changes without writing them. | Pass |
| Lifecycle | `unchanged_reapply` | Apply the same schema twice without creating duplicates. | Pass |
| Lifecycle | `changed_definition` | Update stored role metadata. | Pass |
| Lifecycle | `removed_permission` | Remove a permission and its managed policy row. | Pass |
| Role removal | `assigned_role_removal` | Reject removal of a role that still has assignments. | Pass |
| Role removal | `forced_role_removal` | Remove an assigned role with `--force`. | Pass |
| Validation | `invalid_schema` | Reject a role that references an unknown permission. | Pass |
| Priority | `priority_base_winner` | Load conflicting base definitions at priorities 100 and 200. | **Fail** |
| Priority | `priority_base_tie` | Reject conflicting base definitions with equal priority. | Pass |
| Extensions | `extension_add_remove` | Add and remove permissions through a role extension. | Pass |
| Priority | `priority_extension_winner` | Select the higher-priority role extension. | Pass |
| Priority | `priority_extension_tie` | Reject conflicting extensions with equal priority. | Pass |
| Validation | `extension_scope_mismatch` | Reject an extension with an incompatible permission scope. | Pass |
| Validation | `unknown_extension_target` | Reject an extension targeting an unknown role. | Pass |
| Compilation | `identical_duplicate` | Merge identical definitions without duplicating stored records. | Pass |
| Rendering | `multiple_scopes` | Create one policy row for each supported scope. | Pass |
| Definitions | `hidden_role` | Persist a hidden role. | Pass |
| Loading | `malformed_yaml` | Reject malformed YAML without writing state. | Pass |
| Validation | `unsupported_version` | Reject an unsupported schema version. | Pass |
| Discovery | `missing_directory` | Report a missing schema directory. | Pass |
| Existing state | `preexisting_policy_adoption` | Adopt a matching policy row without duplicating it. | Pass |
| Existing state | `unmanaged_policy_preserved` | Preserve an unrelated unmanaged policy row. | Pass |
| Existing state | `preexisting_matching_definitions` | Adopt matching definitions that have no source links. | Pass |
| Existing state | `preexisting_conflicting_definitions` | Reconcile existing metadata with the discovered schema. | Pass |
| Existing state | `preexisting_orphan_definition` | Remove a definition no longer declared by a schema. | Pass |
| Concurrency | `concurrent_stale_apply` | Apply old and updated schemas concurrently. | **Fail** |

## Observations

`priority_base_winner` used two files defining the same category, permission, and role with different metadata. One had priority 100 and the other priority 200. The command rejected the definitions during validation. The compiler behavior and its test expect priority 200 to win, while the ADRs and schema reference do not specify priority behavior for conflicting base definitions.

`concurrent_stale_apply` overlapped an old-schema apply with an updated-schema apply. Both commands succeeded, but the final definitions included both permissions while the Casbin policy included only the permission from the updated schema.

Nearly every command also printed the distribution ownership warning several times, which made the command output difficult to scan:

```text
Could not uniquely resolve the distribution that ships a schema resource; selecting deterministically.
```

## Reproduce

Bootstrap the disposable environment once. This is the slow step:

```bash
make acceptance-bootstrap
```

Run all cases:

```bash
make acceptance
```

Run one case:

```bash
make acceptance-case CASE=initial_apply
```

Generate the summary again for the latest run:

```bash
make acceptance-report
```

Results and raw logs are written under `.tutor-schema-acceptance/results/<run-id>/`. The test environment is separate from the normal Tutor root.
