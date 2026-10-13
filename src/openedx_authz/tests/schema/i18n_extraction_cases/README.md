# Schema i18n extraction cases

Test schemas for `make extract_translations` (openedx/openedx-authz#509). Each directory is added through `OPENEDX_AUTHZ_SCHEMA_DIRECTORIES` next to the real schema in `openedx_authz/authz/schema/`, which stays loaded. The settings module `openedx_authz.settings.i18n_extraction_cases` reads the list of directories from the `AUTHZ_I18N_CASES` environment variable.

```
src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh
uv run python src/openedx_authz/tests/schema/i18n_extraction_cases/compare.py src/openedx_authz/tests/schema/i18n_extraction_cases/results
```

`run.sh` runs cases 01 to 05 together, case 10 alone because it redefines a role from the real schema, and 06 to 09 one at a time, because each of 06 to 09 stops the whole extraction. To run specific cases, pass them as arguments. A comma-separated argument loads those cases in the same run.

```
src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh 02-missing-fields
src/openedx_authz/tests/schema/i18n_extraction_cases/run.sh 01-text-escaping,04-role-extensions
```

Each run saves `make.log`, `exit_code`, `generated_py.out` and `django.po` to `results/<run>/`. The generated module is saved with a `.out` extension because `results/` is inside the package and `makemessages` would otherwise scan it in later runs. `compare.py` parses the `pgettext()` calls in `generated_py.out` and checks that each `(context, message)` pair appears exactly in `django.po`, and that `django.po` has no context entries that weren't generated.

| Case | Exercises | Observed |
|---|---|---|
| 01-text-escaping | Folded `>-` and `>`, literal `\|`, `%` and `%(name)s`, `{name}` and `{{ }}`, single and double quotes, backslash, non-ASCII and RTL text, leading and trailing spaces, identical display name and description, the same display name on two permissions, a description longer than 79 characters | Exit 0. All pairs match `django.po`. `>` and `\|` keep a trailing `\n` in the msgid. Strings with `{...}` get the `python-brace-format` flag |
| 02-missing-fields | Category without `description`, role without `display_name`, permission without `namespace` or `name`, two roles without `id` | Exit 0. Missing fields are emitted as `msgid ""` with a context. Contexts end up as `permission.display_name:.no_namespace`, `permission.display_name:test.` and `role.display_name:`. |
| 03-yaml-coercion | `Yes`, `no`, `123`, `1.50`, `~`, a date, a list and a dict as field values | Exit 0. Emitted as `"True"`, `"False"`, `"123"`, `"1.5"`, `""`, `"2026-10-13"`, `"['a', 'b']"` and `"{'key': 'value'}"` |
| 04-role-extensions | Extension with only `display_name`, only `description`, both, neither, and one for a role that doesn't exist | Exit 0. Only overridden fields are emitted. The extension for the role that doesn't exist is extracted too |
| 05-file-discovery | Same role id in `a_first.yaml` and `b_second.yml` with different text, a `.yml` file, an empty file, a comments-only file and a `.txt` file | Exit 0. `.yml` is discovered and `.txt` is ignored. For the duplicated id, `b_second.yml` wins and the `a_first.yaml` text is dropped without a warning |
| 06-control-chars | Tab, `\r` and `\x04` in field values | Exit 2. The generated module is valid Python. `makemessages` fails with `CalledProcessError: Command 'django-admin makemessages -l en -v0 -d django' returned non-zero exit status 1` |
| 07-entry-not-mapping | `roles: [just_a_string]` | Exit 2. `AttributeError: 'str' object has no attribute 'get'`, with no file name |
| 08-section-is-mapping | `roles:` written as a mapping instead of a list | Exit 2. Same `AttributeError` |
| 09-invalid-yaml | Unclosed flow sequence | Exit 2. `CommandError: Invalid YAML in openedx_authz:tests/schema/i18n_extraction_cases/09-invalid-yaml/invalid.yaml` |
| 10-duplicates | Same role id twice in one file, same permission twice in one file, same role id in `a_high_priority.yaml` (priority 200) and `b_low_priority.yaml` (priority 100), same id and text in both files, a role with the same id as `course_admin` in the real schema, a role extension with the same id as a role | Exit 0. All pairs match `django.po`, one entry per context. In the same file, the second definition replaces the first. Across files, the file that sorts last by path wins, so `b_low_priority.yaml` replaces `a_high_priority.yaml`. The real `course_admin` display name and description are replaced by the test schema's, and "Course Admin" no longer appears in `django.po`. Identical definitions produce one entry. The role extension gets its own `role_extension.` context. No warning in any of these |
