# P4C fix1: INSERT-guard finding closed

**[P2] Exercise rejection at the new shared INSERT guard: ADDRESSED.**

The new `services/platform/apiserver/security_agent_temporal_admission_guard_postgres_test.go:51` subtest calls the authorized retained70 `op02` directly, with a hidden Temporal parent occupying the same definition's only slot. Lines 69-74 assert rejection and an unchanged product snapshot. Lines 78-97 release the controlled parent, admit one retained run, then prove a duplicate makes no further writes. This is the retained admission route the original test did not exercise.

The other subtest reaches the trigger through the retained finding API. At `security_agent_temporal_admission_guard_postgres_test.go:118`, a separate connection holds the organization lock. Lines 131-137 require SQLSTATE40001, the exact organization-busy message and error context naming `zasp_temporal73.capacity_guard`, before the three-second timeout. It cannot pass on a selector skip. Lines 139-166 check rollback, unchanged records, successful retry after lock release, and identical-request replay at capacity one. The snapshot helper at line 173 covers parents, source receipts, audits, request receipts, admissions and65/73 commands.

Mutation sensitivity is now demonstrated. The opt-in helper at `security_agent_temporal_admission_guard_postgres_test.go:194` saves the73 function definitions, replaces the guard with `RETURN NEW`, recomputes and installs a consistent catalog fingerprint, then requires real73/70/72 readiness at line 281. With that mutant, the retained selector admits1 over hidden capacity and the API call succeeds while the organization lock is held. Both intended assertions fail. The deferred restoration at lines 229-246 reinstalls every saved definition and the original registration, compares exact definitions and checks original73/72 readiness.

## New breakage in the fix diff

None identified. The fix changes one new test file and appends the implementation report; production SQL, Go routing, catalog pin and original tests are unchanged. The mutation runs only when explicitly requested inside the disposable fixture. Its cleanup precedes fixture teardown, including after failed subtests.

## Checks and covering evidence

I used the Superpowers scoped re-review template and read the 343-line fix diff once against the original reviewed dirty-source baseline. I checked the prior finding, appended fix report, new assertions and mutation/restore code. The fixture's supplied PostgreSQL factory is `startDisposablePostgresAs` at `services/platform/apiserver/security_agent_temporal_domain_postgres_test.go:68`.

I independently confirmed fix manifest SHA-256 `3ad2e2caa8dd20ef83b2d2aab762132fa16ca754ed097d3690398c477a910bfd`. The controller's 34-hash verification and reverse-diff check cover the remaining packet/source comparisons.

`p4c-fix1-guard-red.log` is correctly labeled a setup failure. It does not count as behavioral proof.

`p4c-fix1-guard-red2.log` shows both intended failures with valid mutant readiness, exact restoration and a normally joined owned PostgreSQL process. The package result is expected FAIL20.318s.

`p4c-fix1-guard-green.log` shows PASS72.409s for `TestTemporalAdmissionRetainedInsertGuardPostgres` and the original expanded `TestTemporalAdmissionScheduledInstalledPostgres`. Both disposable PostgreSQL processes joined normally. The guard subtests pass, including the explicit trigger-context contention assertion. These existing results cover the fix; I ran no suite or diagnostic test.

## Out-of-scope observations

None newly identified. The already-recorded wider occupancy-family matrix, lease-free executor,73 start consumption, full P4C routing and deployed gates stay open. This round does not reopen unchanged code or approve runtime activation.

## Round verdict

**All findings addressed, no new Critical/Important breakage.** Spec and quality acceptance pass for the admission/accounting checkpoint at this fix. Proceed with the approved next slice; keep full P4C and production acceptance separate.
