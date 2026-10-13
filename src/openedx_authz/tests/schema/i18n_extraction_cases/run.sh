#!/usr/bin/env bash
# Run `make extract_translations` with test schemas added next to the real schema,
# and save the outputs to results/<run>/ (make.log, exit_code, generated.py, django.po).
#
# Each argument is one run: a comma-separated list of case directories loaded together.
# Without arguments, cases 01-05 run together and 06-09 run one at a time, since
# each of 06-09 stops the whole extraction.
#
#   src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh
#   src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh 02-missing-fields
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
CASES="$REPO/src/openedx_authz/tests/schema/i18n_extraction_cases"
GENERATED="$REPO/src/openedx_authz/engine/schema/_generated_translations.py"
PO="$REPO/src/openedx_authz/conf/locale/en/LC_MESSAGES/django.po"

runs=("$@")
[ ${#runs[@]} -eq 0 ] && runs=(
  "01-text-escaping,02-missing-fields,03-yaml-coercion,04-role-extensions,05-file-discovery"
  06-control-chars 07-entry-not-mapping 08-section-is-mapping 09-invalid-yaml
)

for run in "${runs[@]}"; do
  name="${run//,/+}"
  [ ${#name} -gt 60 ] && name="${run%%,*}+others"
  out="$CASES/results/$name"
  rm -rf "$out" && mkdir -p "$out"
  rm -f "$GENERATED" "$PO"

  (cd "$REPO" && DJANGO_SETTINGS_MODULE=openedx_authz.settings.i18n_extraction_cases \
    AUTHZ_I18N_CASES="$run" uv run make extract_translations) > "$out/make.log" 2>&1
  echo $? > "$out/exit_code"
  [ -f "$GENERATED" ] && cp "$GENERATED" "$out/generated.py"
  [ -f "$PO" ] && cp "$PO" "$out/django.po"
  echo "$run: exit $(cat "$out/exit_code")"
done
