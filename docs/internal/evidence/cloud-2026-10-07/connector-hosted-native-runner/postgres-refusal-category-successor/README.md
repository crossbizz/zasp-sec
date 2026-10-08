# PostgreSQL startup refusal category diagnostics

Run 37724786477 on 3a33d2ffe681dce082c3713b60db22ff6f9769bf failed normally at the postgres-start fixture stage before database connection or any original subcase. Restoring the known-working child-library environment was insufficient. The original refusal annotations are retained; no sole cause is asserted.

This independently reviewed successor changes only the safe native-output diagnostic. It maps fixed PostgreSQL startup, loader, permission, path, version, locale and extension markers to deduplicated enum labels. It publishes no raw output, paths, SQL parameters or credentials. All original execution, nine subcases, source pins, assertions, deadlines, resource floors and process cleanup remain unchanged. Labels can overlap and require actual observation; source review is not native acceptance or deployment proof.
