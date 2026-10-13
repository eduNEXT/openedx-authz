# Schema i18n extraction cases

Test schemas to check what `make extract_translations` generates for edge cases (openedx/openedx-authz#509). The real schema stays loaded, and each case is added next to it.

## How to run

1. Check out this branch and install the dependencies:

   ```
   git fetch https://github.com/edunext/openedx-authz.git MJG/schema-i18n-extraction
   git switch --detach FETCH_HEAD
   uv sync --all-groups
   ```

2. Run every case from the repository root:

   ```
   src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh
   ```

   Each run prints its exit code and saves `make.log`, `exit_code`, `generated_py.out` (the generated module) and `django.po` to `results/<run>/` in this folder.

3. Check that every generated `pgettext()` call made it into the `.po`:

   ```
   uv run python src/openedx_authz/tests/schema/i18n_extraction_cases/compare.py src/openedx_authz/tests/schema/i18n_extraction_cases/results
   ```

To run only some cases, pass their folder names. Names joined with a comma run together:

```
src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh 02-missing-fields
src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh 01-text-escaping,04-role-extensions
```

Without arguments, 01 to 05 run together, and 06 to 10 run one at a time. Cases 06 to 09 stop the extraction, and case 10 redefines `course_admin` from the real schema.

## Cases

| Case | What it contains |
|---|---|
| 01-text-escaping | Quotes, backslash, non-ASCII and RTL text, `%`, `{}`, leading and trailing spaces, a long description, `>-`, `>` and `\|` block scalars, the same text as display name and description, the same display name on two permissions |
| 02-missing-fields | A category without `description`, a role without `display_name`, permissions without `namespace` or `name`, two roles without `id` |
| 03-yaml-coercion | `Yes`, `no`, `123`, `1.50`, `~`, a date, a list and a dict as field values |
| 04-role-extensions | Extensions with only `display_name`, only `description`, both, neither, and one for a role that doesn't exist |
| 05-file-discovery | The same role id in two files, a `.yml` file, an empty file, a comments-only file and a `.txt` file |
| 06-control-chars | Tab, `\r` and `\x04` in field values |
| 07-entry-not-mapping | `roles: [just_a_string]` |
| 08-section-is-mapping | `roles:` written as a mapping instead of a list |
| 09-invalid-yaml | An unclosed flow sequence |
| 10-duplicates | The same role id twice in one file, the same permission twice in one file, the same role id in files with priority 200 and 100, the same id and text in two files, a role with the same id as `course_admin`, a role extension with the same id as a role |
