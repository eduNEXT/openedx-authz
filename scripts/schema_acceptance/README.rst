Schema pipeline acceptance checks
=================================

These disposable checks run the real ``load_authz_schema`` command inside a
Tutor development CMS container. They use a dedicated Tutor root and identifiers
prefixed with ``acceptance_``.

Bootstrap the environment once. This is the slow command::

    make acceptance-bootstrap

Then run one case or all cases::

    make acceptance-case CASE=initial_apply
    make acceptance

The suite covers initial apply, dry-run behavior, idempotency, definition and
permission changes, role-removal gates, priority resolution, extension
conflicts, duplicate definitions, scope validation, malformed input, source
attribution, unmanaged-policy preservation, pre-existing definitions, and a
concurrent stale-policy apply. Run the script without arguments to print every
accepted case name after the resulting error message::

    make acceptance-case CASE=list

Output is saved under ``.tutor-schema-acceptance/results``. Every run creates a
``report.md`` summary with pass/fail status and links to each case's raw log.
``make acceptance`` runs every case and reports all failures at the end, so one
observed defect does not hide later results. Generate the report again for the
latest or a named existing run with::

    make acceptance-report
    make acceptance-report RUN=20261002-151610

``priority_base_winner`` checks how priority affects conflicting base
definitions. The ADRs and schema reference do not specify this case. The
compiler selects the higher-priority definition, while the document validator
may reject the conflict before compilation. A failure records that behavior.

``concurrent_stale_apply`` intentionally overlaps an old-schema apply with an
updated-schema apply. The current pipeline has no lock around its plan and apply
phases. The case requires the updated schema to be the final consistent state;
a failure captures the race and its resulting database state.

Environment commands::

    make acceptance-status
    make acceptance-up
    make acceptance-down
    make acceptance-destroy CONFIRM_DESTROY=yes

The destroy target accepts only the repository's
``.tutor-schema-acceptance`` directory and refuses the normal Tutor root.
