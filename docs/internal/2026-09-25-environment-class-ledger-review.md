SPEC: PASS for the M2-46b ledger correction.

QUALITY: APPROVED. No Critical, Important or Minor findings.

## A name doesn't save a class

The demotion is supported. Original M2-46b verification requires setting production/staging/development and saving (`docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md:1670`), while the PRD identifies these as Environment categories (`docs/internal/agent_security_platform_PRD_v1.5.md:888`). The current form edits names. Calling its created row "Staging" doesn't change the stored development class.

I used the Superpowers task-review process and reviewed only the supplied baseline-relative diff, brief, report, retained terminal evidence and the specific product boundaries needed to check this conclusion. File references here are relative to `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`. The packet is `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-environment-class-ledger/`.

The focused source check agrees with the report: `app/features/identity/ScopeOnboardingView.tsx:20` accepts names in its create/update interface, lines 31-32 send name-only bodies, and lines 93-95 select existing environment IDs or edit names. Its test at `app/features/identity/ScopeOnboardingView.test.tsx:39` renames an option and creates a Staging label, without asserting class selection or persistence.

`openapi/openapi.yaml:4816` accepts workspace_id/name for creation, and update points to NameInput at line 321. The handler reads only Name for update and WorkspaceID/Name for creation (`services/platform/apiserver/production.go:662` and `:679`). SQL creation fixes development; update changes name/version (`services/platform/apiserver/administration_repository.go:37` and `:38`). The schema stores environment_class separately and constrains it (`services/platform/migrations/sql/0007_production_administration.up.sql:81`). I didn't inspect unrelated product behavior.

## One row, consistent bookkeeping

The diff changes only M2-46b's classification. `docs/internal/implementation_production_availability_v1.5.tsv:167` preserves Complete and name-form evidence, assigns component-only and T11-identity-admin, and states the remaining class-selection/persistence work. The owner-map and crosswalk rows at line 167 agree; the crosswalk retains the original verification and P7/P8 scope.

The remaining changes are the current prose and totals, the explicit component-only audit entry, one regression test and two affected count fixtures. Historical paragraphs and product code are absent from this delta. I treated the saved six-file baseline as authoritative, not clean HEAD; the controller reports verifying all 18 baseline/current/evidence hashes.

I independently recounted the current TSV with read-only AWK: 728 rows, 523 production-available, 144 component-only, 61 blocked/external, zero missing-class entries. M2 is 67 production-available and 5 component-only, totaling 72. These agree with `scripts/implementation-status-check.mjs:22`, its M2 map at line 32, and the status opening, summary and milestone matrix at `docs/internal/implementation_status_v1.5.md:93`, `:6263` and `:6470`.

## The guard exercises the validator

`scripts/implementation-status-check.test.mjs:43` tests actual promotion acceptance, not source text. Its mutation works against either the old production row or the corrected component-only row. The assertion requires the exact M2-46b audited-component refusal; unrelated count errors cannot make it pass. It then checks Complete, component-only and the concrete owner.

The explicit entry at `scripts/implementation-status-check.mjs:85` is necessary. M2-46b isn't in the production allowlist, and T11-identity-admin isn't an audited-class owner at line 58. Removing the component-only entry would remove the required task-specific error from the classifier at line 282, so the new regression would fail even if generic count errors remained. This meets the brief's future-rule-removal requirement.

The count fixtures at `scripts/implementation-status-check.test.mjs:356` and `:580` now expect 522 versus 523 and mutate the current summary's 523 row. The other 39 tests remain in the scoped diff.

## Retained results, not fresh runs

I read all three terminal logs. `terminal/red.log` records exit 1 and "Missing expected rejection" from the real validator, one failed test, 108.313875ms. This is the requested behavioral RED. `terminal/green.log` records exit 0, 40 passes, zero failures/skips, 475.374292ms. `terminal/validator.log` records exit 0 and 728 / 523 / 144 / 61 / 0. No unresolved warning appears in those outputs.

I did not rerun tests or the validator, alter source, launch agents, operate services or change git state. This review writes only its report. The prior M7A-25 wording correction is outside this delta and wasn't reopened.

This accepts ledger honesty, not the Environment feature. Custom/test taxonomy, class-transition rules, product/UI implementation, persistence acceptance and deployment remain unverified here. Keep M2-46b component-only until its original verification has evidence.
