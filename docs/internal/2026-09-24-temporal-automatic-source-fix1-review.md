# P4C automatic-source fix1 review

Spec compliance: rollout correction complies with the revised fix brief; overall stage acceptance remains blocked by Important 2.

Code quality: no new issues found in the fix1 delta. Diagnostic coverage is suitable for the approved bounded investigation, with the limits below; it does not establish reliability.

Original Important 1: **ADDRESSED**, within the current-application correction and explicit rollout prerequisites.

Original Important 2: **NOT ADDRESSED** as a reliability finding. The first cause remains unknown.

Counts: new findings Critical 0 / Important 0 / Minor 0. Remaining original findings Critical 0 / Important 1 / Minor 1. The original UI-warning Minor is explicitly deferred outside this round, not resolved or reopened here.

## Review boundary

Read the fix1 review brief first, copied fix requirements and revised worker ruling, original review, implementation report's fix chronology, and all 974 lines of `stage1-relative.patch`. This compares 19 fix1 source paths to frozen stage1, not HEAD. The controller verified the 19 live source and 152 evidence hashes. The retained static check reports all 216 historical SQL files and 88 frozen stage1 copies unchanged (`E/fix1-static-checks.log:2`). No SQL, fingerprint or dependency change appears in this delta.

`E` below means `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-automatic-source-evidence/logs/`. Other paths are worktree-relative. Review was read-only except this report: no tests, source/Git writes, nested agents, acceptance or publication. The other owner's `authorization/**` work was not reviewed.

## Important 1: rollout correction

The new body gate checks rule presence and, for configured bodies only, requires the current API principal's exact 77 checksum/fingerprint readiness (`services/platform/apiserver/security_agent_automatic_authority.go:12`). Current non-delete security-agent mutations call it (`services/platform/apiserver/workflow_repository.go:166`). Activation reads the persisted tenant-scoped definition, verifies its identity and applies the same rule gate, rather than trusting an incoming rule flag (`security_agent_automatic_authority.go:36`). Both the existing activation repository and public62 activation operations invoke this check (`security_agent_repository.go:324`; `security_agent_public62_repository.go:127`). Reads/deletion remain outside the new requirement; omission does not acquire a 77 API requirement.

The actual tracing wrapper now forwards all four optional 74 definition methods, returning underlying errors and preserving absent/unhandled fallback (`services/platform/agentsec-api/temporal_test_definition_runtime.go:12`). This fixes the concrete mounted route that previously selected legacy55 despite 74 support.

Under the revised worker ruling, exact ready77 is a prerequisite for automatic-selector startup. The constructor refuses mismatched selector/automatic-source availability; current projection/readiness refuses absent or invalid77, and retained selector Activity admission rechecks readiness before calling 75 (`services/platform/agentsec-worker/security_agent_temporal_runtime.go:225`; `temporal_test_selector.go:23`, `:143`). Omitted definitions still use 75 admission under ready77. No executor grant or borrowed API identity was added.

Evidence supports this correction:

- Meaningful installed RED shows configured manual and automatic creates returning 201, updates returning 200 and stored activation succeeding before the fix (`E/fix1-rollout-red2.log:4`, `:8`). The resulting 77 preflight refusal is protective behavior, not a migration defect.
- Mounted composition RED shows legacy55 selected in all six cases and absent/invalid selector admission succeeding (`E/fix1-composition-red1.log:28`, `:54`, `:170`). The covering installed, mounted and Activity groups pass in `E/fix1-gates-green1.log:14`, `:159`, `:172`.
- Extended installed-role coverage passes with explicit executor-principal confirmation for absent, ready and invalid modes (`E/fix1-rollout-extended2.log:9`, `:19`, `:25`, `:30`). The test checks configured create/update/stored activation refusal, unchanged drafts, both public62 activation operations, ready activation transitions, invalid-catalog refusal and one actual omitted-definition 75 admission (`services/platform/apiserver/temporal_automatic_rollout_postgres_test.go:80`, `:140`, `:205`, `:215`). Three actual 42501 reader denials support the revised worker prerequisite instead of unauthorized per-definition inspection.
- The affected Human case passes with 77 installed (`E/fix1-connected-compat-diagnostic2.log:21`). That batch still fails because its selector helper used `automatic=false`; the one-line fixture correction matches the installed77 premise and leaves the lock assertion intact. The selector-only run then proves lock/current revision, real Schedule admission, preservation of admitted work on disable and current grant-revocation refusal (`E/fix1-selector-compat-green1.log:4`, `:12`, `:14`, `:23`). These are separate case results, not a passing combined batch.

This verdict does not repair old binaries or direct historical pre77 SQL. Install and verify 77 before replacing automatic workers, retain the old worker until the replacement is ready, and retire rule-blind older workers before enabling configured definitions. Violating that sequence can make automatic processing unavailable or expose old-protocol behavior. These remain release gates; 77 is still unpublished.

## Important 2: diagnostics improved, cause unresolved

The constructor-only, unexported diagnostic hook defaults to nil, delegates the same executor and product before registration, and introduces no retry, deadline, provider resend or dispatch-guard change (`services/platform/agentsec-worker/production_runtime.go:45`; `security_agent_temporal_runtime.go:206`; `security_agent_temporal_single_product.go:14`). Test wrappers restrict output to Workflow/run/attempt, static operations/phases/errors, safe state booleans and SQLSTATE/function identifiers when available (`temporal_automatic_first_error_test.go:34`, `:63`, `:117`). The default/decorated product identity check passes (`E/fix1-diagnostic-compile1.log:3`).

Both bounded same-sequence diagnostics observed first and later SingleTest executions only on attempt 1, with no error in the 27 diagnostic records for each execution. Product.Test succeeds in `E/fix1-first-error-native1.log:43`, `:77` and `E/fix1-connected-compat-diagnostic2.log:74`, `:108`. Exact mounted HTTP/repository equality also passes (`:84` and `:115`, respectively). The first command passes 165.968s; the second Native case passes 245.79s inside the separately failing selector batch. Neither run reproduced the original failure.

The diagnostic is not complete first-error proof. The unchanged database classifier retains PgError for default joined errors but replaces explicit conflict/operation/not-found categories with sentinels (`services/platform/apiserver/postgres_database.go:490`). Accordingly, SQLSTATE/function may be unavailable for a future failure in those categories. The packet discloses this; no failing category justified another driver seam in this bounded round.

The original evidence still shows SingleTest retry exhaustion at scheduled event 23 / failed event 25, cleanup completion and Workflow failure, without the first application/database cause (`E/sources-native-history-diagnostic1.log:31`, `:35`, `:42`, `:46`). Successful later runs are not a root cause or fix. Important 2 remains an unresolved release/acceptance gate. The user's approval to stop bounded repetition and continue independent work is compatible with this verdict; it is not acceptance of the failure or proof of production readiness.

## Focused source checks and remaining limits

The selector diff cuts the surrounding functions. I read their local context to confirm the new protocol gate still feeds readiness/current projection and retains the advisory-lock/current-read sequence. Separately, the named risk of lost diagnostic SQLSTATE warranted reading only the unchanged QueryJSON/error-classification boundary; the limitation above is confirmed. No wider route or source audit was performed.

No new fix-diff breakage was identified. Full 728-requirement preservation remains binding but is not re-proved by this round. Other automatic responder families, potential/runtime execution, ordered configured admission and original M7A-35 through M7A-38d stay open. Controlled provider/storage/OpenFGA/identity fixtures are not production Stytch, OpenFGA enforcement, real-provider or deployment proof. This report permits no migration publication or stage acceptance.
