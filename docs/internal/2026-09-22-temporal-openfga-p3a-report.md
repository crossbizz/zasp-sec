# P3A staged ownership and admission

Date: 2026-09-22. Worktree: `.worktrees/cached-runtime-ship-20260917`, HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a` with the existing dirty P0/P1/P2 overlay retained.

P3A implements the first approved dependency slice. It does **not** complete P3, activate Temporal execution, or demonstrate a production provider flow. The controller approved P3A ownership/admission, followed by P3B lease-free domain authority and P3C deterministic workflow/composition. Independent review is pending.

## Implemented boundary

Additive extension66 introduces private, immutable scoped run ownership. Admission chooses the owner while holding the run lock, in the same transaction as the run, audit, receipt and outbox insert. Fresh queued, unclaimed, unplanned, unbudgeted runs can use an explicitly installed route. Existing runs and commands are not bulk-converted. Decision commands inherit the run's retained owner. The shipped route table is empty and no runtime principal has an activation grant or API.

Temporal ownership excludes old execution sessions from runs and effects through restrictive policies. The policy evaluates the registered API login using `session_user` through the existing principal authority, rather than trusting a supplied role name or GUC. API decisions retain their existing authorization. BEFORE mutation guards also reject legacy run/effect lease fields, even under a superuser that bypasses RLS. This prevents fake scheduler tokens from becoming effect authority. The guards and policies are bound into66 readiness.

The upgraded repository uses66 manual-start, run-read and cancellation facades. Each copies the validated predecessor business function and replaces only its entry name and readiness call. No historical58/60 readiness function is relaxed. An absent66 retains the existing legacy route; installed but invalid66 fails closed. Actual API database composition forwards the capability through its tracing wrapper. Public62 ordered admission and manual admission now work on the same registered61 installation, including retained optional63/64.

When63/64 exist,66 validates their exact predecessor identities, revokes the obsolete worker's callable function grants atomically, and retains their schema, functions, registration, leases and evidence. Immutable retirement records bind their original and post-transition fingerprints.66 readiness checks the retired catalogs and denies restored worker execution privileges. The old migration runner refuses independent installation, restoration or removal of63/64 after66. Unrelated domain grants are retained.

`agentsec-migrate up-temporal-ownership` is the shipped extension command. Its registration branch verifies the already-registered migration login and66 readiness without re-registering unrelated principals. Extension version66 does not rewrite the base release61 ledger.

Current66 fingerprint: `422b211febdd6e2b37882dc3f5961a79ca5c58f3f87f1642f7babf1224fbe94a`.

## Product checks and grouped TDD

Superpowers grouped TDD drove admission, ownership and retirement behavior. Verification used disposable owned PostgreSQL instances and actual API, Security Agent worker, action and deployment logins. No vendor conformance suite or new scheduling state machine was added.

Commands run from `services/platform`:

1. `go test ./apiserver -run '^TestTemporalOwnershipAdmissionPostgres$' -count=1 -v`
   Initial RED: the ownership migration interface/constants were absent. Subsequent focused REDs exposed the unregistered66 catalog fingerprint and the ability to install the obsolete worker after66. The latter gained an explicit post66 migration refusal. SQL syntax and test-input errors encountered while building the fixture were corrected; they are not counted as product RED evidence.
2. `go test ./apiserver -run '^TestTemporalManualFacadeRouting$' -count=1 -v`
   RED: the real repository returned `repository unavailable` rather than selecting the66 facade. GREEN after capability selection and tracing composition were implemented. The test also checks that invalid66 cannot fall back to old readiness.
3. `go test ./apiserver ./agentsec-api ./agentsec-migrate -run '^Test(TemporalOwnershipAdmissionPostgres|TemporalManualFacadeRouting|SecurityAgentManualStart|SecurityAgentManualHTTPPostgres|RuntimeServices.*)$' -count=1 -v`
   GREEN, exit0: apiserver48.961s, agentsec-api1.747s, agentsec-migrate1.132s. The migrate package compiled but this expression selected no package-local tests. The actual CLI command ran as a subprocess inside the PostgreSQL ownership test. Existing manual HTTP and manual-start regressions passed.
4. Additional direct authority probes were added without production changes. A cleanup probe initially failed input validation because its effect version was zero. With a valid version, focused registered61 verification passed in24.681s. These probes assert `ordered run absent`, not merely any error, after valid wire/principal/readiness checks and seeded organization/budget lock prerequisites.
5. Final grouped ownership/facade command: `go test ./apiserver -run '^Test(TemporalOwnershipAdmissionPostgres|TemporalManualFacadeRouting)$' -count=1 -v`. GREEN, exit0,43.290s; registered61 case20.93s and retained63/64 case21.18s. Its retained output is `p3a-final-tests.log` in the evidence directory.

The PostgreSQL group proves:

- Shipped CLI66 first installation on the exact registered61/public62/outbox65 fixture, followed by replay through the runner. The optional63/64 installation is upgraded through the same runner used by the command.
- Ordered admission stays legacy by default. Only a superuser in the disposable fixture sets a Temporal candidate route. Manual admission then commits a Temporal-owned outbox start, stable receipt replay and manual provenance on that same database.
- Admission rollback removes ownership, deactivated requester replay fails, stale definition version fails, and duplicate admission produces one command/owner pair.
- Real repository run-read preserves manual provenance. Real repository cancellation produces a decision command with the same Temporal owner and committed receipt identity.
- The granted old budgeted selector excludes the Temporal run. Private61 planning claim/reconcile/start refuse specifically at its run read.
- Actual action application and cleanup claim/heartbeat, private61 test-action claim/heartbeat, and deployment claim refuse specifically at the ownership-filtered run read. The action/recovery selector does not expose the run. The probe fixture supplies lock prerequisites only, not simulated provider success, approval or cleanup evidence.
- Superuser run lease UPDATE and effect lease INSERT fail with `Temporal run rejects legacy execution authority`, independent of RLS. Ownership UPDATE is refused.
- API role cannot activate a route, rewrite ownership or change command ownership. Removing a run guard, ownership policy or capture trigger makes66 readiness false.
- Retained63/64 entry calls are denied by function ACL under the real old worker, and neither old extension can be installed after66.

These checks cover admission and legacy claim fences. They do not exercise a linked child category journal after a real Temporal effect, a provider call, a Temporal workflow, or compensation. Lease-free linked-test authority and its real worker/adapter evidence remain P3B obligations.

## Installation portability remains unresolved

The fresh bootstrap attempt failed **before66**, in unchanged release61 final readiness:

`go test ./agentsec-migrate -run '^TestTemporalOwnershipShippedCommandPostgres$' -count=1 -v`

Expected61: `6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92`.

Actual61: `7c225146d18715e24bc74d8a2cbdb8e6cdb91736818eb71d8f3d612d39c18958`.

The controller isolated fixture-specific table/function-owner names in private61 `lock_scope` and `pricing_lock_scope` ACL identities. The established progression fixture builds56/57/58/59/60/61 with its existing `zasp_e2e` owner and gets the exact registered fingerprint. The CLI bootstrap fixture uses `zasp_test` and fails61. See `docs/internal/2026-09-22-release61-owner-portability.md`.

The reproducer and full hashes are retained in `p3a-cli61-regression.go.txt` and `p3a-cli61-red.md`. The knowingly failing test was removed from the active package after controller instruction; it is not silently marked green. No owner was renamed and no historical pin changed. The successful CLI66 check is registered-upgrade evidence only, **not fresh-install acceptance**.

Required follow-up is an additive Temporal install/cutover supporting clean60 and retained61 with explicit portable owner/ACL checks, then retirement of obsolete readiness dependencies. Do not normalize or wrap the old public61 readiness ad hoc: public61 fingerprints include those function identities. Full P3 and publication remain blocked on this repair.

## Unfinished dependency slices and activation gates

P3B must extract lease-free planning, application, signed delivery/readback, linked-test execution/journaling and cleanup authority. Preserve tenant, current membership/permission, approval, immutable version, budget, effect generation and receipt checks. Replace the downstream `ZASP_RED_TEAM_RUN_LEASE` contract explicitly. Stable business-effect identity must survive overlapping Activity attempts, with unknown outcomes reconciled before another send. Keep signing-key preflight before IO and artifact scope/version/hash/body checks. Narrow compensation must remain usable after initiating-user deactivation without granting unrelated effects.

The next authority cannot simply reuse the old worker login:66 currently exposes Temporal-owned rows only to the registered API and rejects legacy leases. P3B needs a separately bound domain executor/compensation boundary and an additive, fingerprint-bound visibility/readiness transition. The repository interface to preserve or deliberately advance is `TemporalAdmissionAvailable`; its66 manual/read/cancel functions currently bind to public62/outbox65 and thus still depend on registered61. No replacement interface is invented in P3A.

P3C must implement `SecurityAgentWorkflow(workflow.Context, StartRequest) error`, explicit Activity policies and deterministic ordering; no `Tick` wrapper. Preserve P2 workflow name `SecurityAgentWorkflow`, workflow ID `security-agent/v1/<organization>/<workspace>/<environment>/<run>`, and signal `product-decision`. Load the committed decision receipt and bound audit/approval evidence. Workflow history must contain scoped IDs, digests and redacted summaries, not secrets or resource bodies. Cancellation uses disconnected-context cleanup and must retain pending/unknown outcomes until verified receipts establish completion.

Actual API -> Temporal worker -> product receipt -> API read evidence is **not present in P3A**. Here the proven path ends at product admission/decision receipts and outbox ownership; worker claims are deliberately rejected. P3C must connect the real runtime with legitimate signing keys and prove the full path before any route is activated. P7 active OpenFGA model/revision fencing, P8/P10 UI/deployed provider acceptance, retention/closed-workflow handling and real cleanup evidence remain required. Do not deploy this staged retirement alone as a functioning replacement for63/64.

## Scope and evidence

Pre-edit bytes: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3-baseline/platform/`. The directory also retains `pre-edit-platform.diff` and `pre-edit-status.txt`.

Final artifacts in that execution-plan directory: `p3a-scoped.diff`, `p3a-hashes.json`, `p3a-final-tests.log`, and the reproducible `p3a-capture-evidence.mjs`. The scoped diff compares against the captured dirty platform bytes, not HEAD. The hash manifest includes every changed source path and the report hash, plus a historical-SQL preservation check.

Changed source paths, all under `services/platform/`:

- `agentsec-api/production_runtime.go`
- `agentsec-migrate/bootstrap_release.go`
- `agentsec-migrate/main.go`
- `apiserver/security_agent_manual_start.go`
- `apiserver/security_agent_repository.go`
- `apiserver/security_agent_temporal_capability.go`
- `apiserver/security_agent_temporal_manual_test.go`
- `apiserver/security_agent_temporal_ownership_postgres_test.go`
- `migrations/production_security_agent_scheduler.go`
- `migrations/production_security_agent_worker.go`
- `migrations/production_temporal_ownership.go`
- `migrations/sql/0066_production_temporal_ownership.down.sql`
- `migrations/sql/0066_production_temporal_ownership.up.sql`

Historical migration SQL through65 is unchanged. No toolchain, UI, dependency-lock or unrelated source changes were made by this slice. No commit, push, production database operation, provider effect or activation occurred.
