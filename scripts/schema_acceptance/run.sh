#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
tutor_bin=${TUTOR:-tutor}
acceptance_root=${ACCEPTANCE_TUTOR_ROOT:-"${repo_root}/.tutor-schema-acceptance"}
fixtures_in_container=/openedx/openedx-authz/scripts/schema_acceptance/fixtures
state_script=/openedx/openedx-authz/scripts/schema_acceptance/state.py
results_dir=${acceptance_root}/results

die() { echo "error: $*" >&2; exit 1; }

validate_root() {
    acceptance_root=$(mkdir -p "$acceptance_root" && cd "$acceptance_root" && pwd -P)
    [[ "$acceptance_root" == "$repo_root/.tutor-schema-acceptance" ]] || die "refusing Tutor root outside $repo_root/.tutor-schema-acceptance"
    [[ "$acceptance_root" != / ]] || die "refusing root directory"
    normal_root=$($tutor_bin config printroot)
    [[ "$acceptance_root" != "$normal_root" ]] || die "refusing normal Tutor root $normal_root"
}

tutor_acceptance() { "$tutor_bin" --root "$acceptance_root" "$@"; }

cms() {
    tutor_acceptance dev exec -T \
        -e "PYTHONPATH=${fixtures_in_container}" \
        -e "ACCEPTANCE_ACTION=${ACCEPTANCE_ACTION:-}" \
        -e "ACCEPTANCE_EXPECT=${ACCEPTANCE_EXPECT:-}" \
        cms bash -lc "cd /openedx/edx-platform && $*"
}

state() {
    ACCEPTANCE_ACTION=$1 ACCEPTANCE_EXPECT=${2:-} cms "./manage.py cms shell < ${state_script}"
}

apply_schema() {
    local fixture=$1
    shift
    cms "./manage.py cms load_authz_schema --dir acceptance_schema/${fixture} $*"
}

expect_failure() {
    local fixture=$1
    shift
    set +e
    apply_schema "$fixture" "$@"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || die "${fixture} unexpectedly succeeded"
    echo "Observed expected failure for ${fixture} (exit ${status})."
}

run_case_body() {
    local name=$1
    echo "=== ${name} ==="
    state clean
    case "$name" in
        initial_apply)
            apply_schema base
            state assert base
            ;;
        dry_run)
            apply_schema base --dry-run
            state assert empty
            ;;
        unchanged_reapply)
            apply_schema base
            apply_schema base
            state assert base
            ;;
        changed_definition)
            apply_schema base
            apply_schema metadata_changed
            state assert metadata_changed
            ;;
        removed_permission)
            apply_schema base
            apply_schema permission_removed
            state assert permission_removed
            ;;
        assigned_role_removal)
            apply_schema base
            state assign
            expect_failure role_removed
            state assert assigned_preserved
            ;;
        forced_role_removal)
            apply_schema base
            state assign
            apply_schema role_removed --force
            state assert role_removed
            ;;
        invalid_schema)
            expect_failure invalid
            state assert empty
            ;;
        priority_base_winner)
            apply_schema priority_base_winner
            state assert metadata_changed
            ;;
        priority_base_tie)
            expect_failure priority_base_tie
            state assert empty
            ;;
        extension_add_remove)
            apply_schema extension_add_remove
            state assert extension_applied
            ;;
        priority_extension_winner)
            apply_schema priority_extension_winner
            state assert priority_extension_winner
            ;;
        priority_extension_tie)
            expect_failure priority_extension_tie
            state assert empty
            ;;
        extension_scope_mismatch)
            expect_failure extension_scope_mismatch
            state assert empty
            ;;
        unknown_extension_target)
            expect_failure unknown_extension_target
            state assert empty
            ;;
        identical_duplicate)
            apply_schema identical_duplicate
            state assert base_attributed
            ;;
        multiple_scopes)
            apply_schema multiple_scopes
            state assert multiple_scopes
            ;;
        hidden_role)
            apply_schema hidden_role
            state assert hidden_role
            ;;
        malformed_yaml)
            expect_failure malformed_yaml
            state assert empty
            ;;
        unsupported_version)
            expect_failure unsupported_version
            state assert empty
            ;;
        missing_directory)
            expect_failure directory_that_does_not_exist
            state assert empty
            ;;
        preexisting_policy_adoption)
            state seed_policy
            apply_schema base
            state assert base_attributed
            ;;
        unmanaged_policy_preserved)
            state seed_unmanaged
            apply_schema base
            apply_schema role_removed
            state assert unmanaged_preserved
            ;;
        preexisting_matching_definitions)
            state seed_definitions
            apply_schema base
            state assert base_attributed
            ;;
        preexisting_conflicting_definitions)
            state seed_conflicting_definitions
            apply_schema base
            state assert base_attributed
            ;;
        preexisting_orphan_definition)
            state seed_orphan_definition
            apply_schema base
            state assert base_without_orphan
            ;;
        concurrent_stale_apply)
            apply_schema base
            state hold_role_lock &
            lock_pid=$!
            sleep 2
            apply_schema base &
            old_pid=$!
            apply_schema permission_removed &
            new_pid=$!
            wait "$lock_pid"
            wait "$old_pid"
            wait "$new_pid"
            state assert concurrent_updated
            ;;
        *) die "unknown case '$name'" ;;
    esac
    echo "PASS: ${name}"
}

run_case() {
    local name=$1
    local case_dir=$2
    mkdir -p "$case_dir"
    set +e
    "$0" internal-case "$name" 2>&1 | tee "$case_dir/output.log"
    local status=${PIPESTATUS[0]}
    set -e
    echo "$status" > "$case_dir/status"
    return "$status"
}

case_expects_command_failure() {
    case "$1" in
        assigned_role_removal|invalid_schema|priority_base_tie|priority_extension_tie|extension_scope_mismatch|unknown_extension_target|malformed_yaml|unsupported_version|missing_directory)
            return 0
            ;;
        *) return 1 ;;
    esac
}

build_report() {
    local run_dir=$1
    local report_file="$run_dir/report.md"
    local passed=0
    local failed=0
    [[ -d "$run_dir" ]] || die "result directory does not exist: $run_dir"

    {
        echo "# Authorization schema acceptance report"
        echo
        echo "Generated: $(date --iso-8601=seconds)"
        echo
        echo "| Case | Result | Evidence |"
        echo "| --- | --- | --- |"
        for selected in "${all_cases[@]}"; do
            local log_file="$run_dir/$selected/output.log"
            local status_file="$run_dir/$selected/status"
            [[ -f "$log_file" ]] || continue
            if [[ -f "$status_file" ]]; then
                case_status=$(<"$status_file")
            elif grep -q "^PASS: ${selected}$" "$log_file"; then
                case_status=0
                if ! case_expects_command_failure "$selected" && grep -Eq 'Traceback \(most recent call last\)|Error: Command failed with status|AssertionError:' "$log_file"; then
                    case_status=1
                fi
            else
                case_status=1
            fi
            if [[ "$case_status" == 0 ]]; then
                result="PASS"
                ((passed += 1))
            else
                result="FAIL"
                ((failed += 1))
            fi
            echo "| \`$selected\` | **$result** | [output.log]($selected/output.log) |"
        done
        echo
        echo "Summary: $passed passed, $failed failed."
    } > "$report_file"
    echo "Report: $report_file"
}

all_cases=(
    initial_apply dry_run unchanged_reapply changed_definition removed_permission
    assigned_role_removal forced_role_removal invalid_schema priority_base_winner
    priority_base_tie extension_add_remove priority_extension_winner
    priority_extension_tie extension_scope_mismatch unknown_extension_target
    identical_duplicate multiple_scopes hidden_role malformed_yaml
    unsupported_version missing_directory preexisting_policy_adoption
    unmanaged_policy_preserved preexisting_matching_definitions
    preexisting_conflicting_definitions preexisting_orphan_definition
    concurrent_stale_apply
)

validate_root
command=${1:-help}
case "$command" in
    bootstrap)
        echo "This runs Tutor initialization and may take several minutes: $acceptance_root"
        tutor_acceptance config save
        tutor_acceptance mounts add "cms:${repo_root}:/openedx/openedx-authz"
        tutor_acceptance config save
        tutor_acceptance dev launch --non-interactive --skip-build
        cms "python -m pip install --no-deps -e /openedx/openedx-authz"
        cms "./manage.py cms migrate openedx_authz"
        ;;
    up) tutor_acceptance dev start -d ;;
    status)
        tutor_acceptance mounts list
        tutor_acceptance dev status
        ;;
    down) tutor_acceptance dev stop ;;
    destroy)
        [[ ${CONFIRM_DESTROY:-} == yes ]] || die "rerun with CONFIRM_DESTROY=yes"
        tutor_acceptance dev dc down --volumes --remove-orphans
        rm -rf -- "$acceptance_root"
        ;;
    case)
        selected=${2:-}
        [[ " ${all_cases[*]} " == *" ${selected} "* ]] || die "CASE must be one of: ${all_cases[*]}"
        stamp=$(date +%Y%m%d-%H%M%S)
        run_dir="$results_dir/$stamp"
        status=0
        run_case "$selected" "$run_dir/$selected" || status=$?
        build_report "$run_dir"
        exit "$status"
        ;;
    all)
        stamp=$(date +%Y%m%d-%H%M%S)
        failures=()
        for selected in "${all_cases[@]}"; do
            if ! run_case "$selected" "$results_dir/$stamp/$selected"; then
                failures+=("$selected")
            fi
        done
        build_report "$results_dir/$stamp"
        ((${#failures[@]} == 0)) || die "failed cases: ${failures[*]} (evidence: $results_dir/$stamp)"
        ;;
    report)
        run_dir=${2:-}
        if [[ -z "$run_dir" ]]; then
            run_dir=$(find "$results_dir" -mindepth 1 -maxdepth 1 -type d -print | sort | tail -1)
        elif [[ "$run_dir" != /* ]]; then
            run_dir="$results_dir/$run_dir"
        fi
        [[ -n "$run_dir" ]] || die "no acceptance result directories found"
        build_report "$run_dir"
        ;;
    internal-case)
        run_case_body "${2:-}"
        ;;
    *)
        echo "Usage: $0 {bootstrap|up|status|down|destroy|case NAME|all|report [RUN]}"
        exit 2
        ;;
esac
