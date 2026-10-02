# P4B review: two blockers

Spec verdict: **Issues found.** The frozen P4B replacement drops two existing discovery concurrency protections. Both belong in P4B; P4C's existing-test/shared-capacity work does not defer discovery generation ownership or its organization-wide `max_active_jobs` limit.

Quality verdict: **Needs fixes before local P4B acceptance.** I found two Important issues, no Critical findings and no separate Minor findings. This is not a merge or production-readiness assessment.

## What holds up

The new admission boundary writes the scoped sync, 72-owned run and canonical outbox atomically, without creating a legacy discovery job. Schedule admission exits after validating its receipt; the SQS consumer is the sole collection starter. Present-but-invalid 72 fails closed. Exact registered `session_user` checks, private function ACLs, FORCE RLS, immutable registration and independently compiled catalog pins are present.

The saved precision-51 projection is narrow: it masks the exact new outbox guard row and the saved original self-definition entry. The actual replacement wrapper, helper, saved baseline and outbox guard are covered by the 72 fingerprint. Unrelated historical catalog entries remain live. I found no broad normalization or historical expected-pin refresh in this handoff.

Receipt handling separates replay from permission to send. A prepared page with no result returns unknown, retries use advancing receipt identities, no-IO overlap waits allocate neither a generation nor an effect, and the original deadline reaches every fresh product boundary. Complete-only inventory application and evidence-only settlement are separate. Committed application evidence survives cancellation and expiry.

The artifact cache stores verified bytes, not authorization decisions. Its full storage/tenant/version key, body cloning, size/count bounds, miss reauthorization and borrower-aware shutdown have focused tests. Schedule ceil-grid projection preserves the original SQL occurrence identity, and the compact action prefix retains the full scope digest. Duplicate-start inspection binds both the continued execution and its original checkpoint-zero execution.

## Important 1 [P1]: the retained route can take a generation while 72 already owns collection

Primary changed boundary: [discovery_temporal_start.go:61](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/agentsec-worker/discovery_temporal_start.go:61). The asymmetric SQL fence is at [0072_production_temporal_discovery.up.sql:370](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0072_production_temporal_discovery.up.sql:370).

The new consumer correctly proves positive legacy ownership, then calls the unchanged legacy processor. That processor claims the delivery and calls `GetDiscoveryJobInput` at [execution_runtime.go:122](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/agentsec-worker/execution_runtime.go:122). The repository still invokes `public.zasp_execution_job_input` at [discovery_execution_repository.go:211](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/discovery_execution_repository.go:211). Its installed SQL14 wrapper calls the saved SQL13 body at [0014_typed_inventory_cutover.up.sql:101](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql:101).

That retained body acquires the same integration/provider advisory lock, but its busy predicate joins only `zasp_discovery_job_authorities` and `zasp_discovery_jobs`. It cannot see a 72 owner, which deliberately has neither row. It then reserves `max(generation)+1` ([0013_production_discovery_execution.up.sql:597](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0013_production_discovery_execution.up.sql:597)). The transaction lock serializes reservation calls only; it does not cover provider IO.

A concrete failing order is: 72 prepares generation 1 and leaves its page unresolved; a retained queued job for the same scoped connector is delivered; its old input function reserves generation 2 and the shipped processor enters collection. Both now own provider work. The 72 guard checks its run state, pending effect, connector and deadline, but not that a retained generation has appeared ([0072_production_temporal_discovery.up.sql:393](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0072_production_temporal_discovery.up.sql:393)). If generation 2 commits first, generation 1 can later fail the retained writer's stale-last-good check and settle as `outcome_unknown` after prepare-apply. A 72 run already in unknown state is also invisible to the retained busy predicate.

The opposite order is fenced by 72's legacy-owner query. That is insufficient. Positive queue ownership does not establish exclusive provider-generation ownership.

Fix the additive installed authority so both reservation routes participate in the same scoped ownership fence, including retained resumes and unresolved 72 effects. Keep historical SQL files unchanged and pin every replacement surface. Add installed tests for both acquisition orders, an already prepared or unknown 72 effect, zero second-owner provider IO, and release only after verified terminal evidence. The current coexistence case at [temporal_discovery_test.go:1075](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/agentsec-migrate/temporal_discovery_test.go:1075) checks routing and constructor readiness; it never collects the retained job while 72 owns the resource.

This finding is a source-derived call/SQL trace. I did not add a new installed reproduction during read-only review.

## Important 2 [P2]: Temporal discovery bypasses the tenant concurrency quota

Primary changed boundary: [0072_production_temporal_discovery.up.sql:367](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0072_production_temporal_discovery.up.sql:367), continuing through effect preparation at line 387.

The retained discovery claimant reads `zasp_discovery_execution_quotas.max_active_jobs`, defaults to 4 and refuses a fresh claim when the organization's active discovery count reaches that cap ([0013_production_discovery_execution.up.sql:582](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/sql/0013_production_discovery_execution.up.sql:582)). The new admission/prepare path never reads this quota or counts organization-wide active work. Its only contention predicate is restricted to one integration/provider.

With `max_active_jobs=1`, two 72 runs for different integrations in the same organization can both prepare effects and collect. A retained job can also claim a slot while a 72 run is collecting because the old quota count only sees leased public jobs. Temporal's `MaxConcurrentActivityExecutionSize: cfg.BatchSize` at [discovery_temporal_runtime.go:173](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/agentsec-worker/discovery_temporal_runtime.go:173) is per worker, unrelated to the organization's configured cap; multiple replicas make that distinction explicit.

This drops an application invariant required by the approved design, which says tenant concurrency remains product-owned and a worker concurrency setting is insufficient ([2026-09-22-temporal-openfga-design.md:53](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/docs/internal/2026-09-22-temporal-openfga-design.md:53)). No discovery-quota deferral was authorized.

Preserve a shared organization-wide capacity boundary across 72 and retained owners without restoring a lease scheduler. Capacity waits must grant no effect authority. Define receipt-backed release and uncertainty behavior, preserve the configured cap/default, and test limit 1 across different integrations, both mixed-owner orders, separate tenants and multiple callers. Neither current tenant-isolation tests nor same-connector overlap tests exercise this limit.

## Evidence I checked

I used the requesting-code-review checklist, approved design/execution plan, P4/P4B briefs, integration notes, accepted P4A fix1 review, controller rulings, retirement inventory, final report and scoped overlay. I traced the production changes and the focused tests at their persistence and IO boundaries. I did not review the unrelated dirty checkout as P4B.

All 68 changed-file hashes and 174 log hashes match. I also compared all 204 preexisting baseline SQL files: 202 under `services/platform/migrations/sql` and 2 under `services/platform/tenantrls/sql`, all unchanged. The manifest's count of 202 is its migration-directory count, not SQL drift. `git apply --reverse --check` accepts the scoped diff against current files.

Frozen identities:

- Freeze: `d81bd70cdcb6aec13aa941bbf04a481dc0cb998d6df9a699f847c59300fd4bd9`.
- The scoped diff is `3b81b03d20fa3277e97df662f84bd5606889bc1e7acb00251826dffe9d4fc017`; baseline `2295a42055cc95b007827eb8a6ead2dd2d6c045c32f842b9203c06149bcd9ccc`.
- Manifest `047a15c924730e3cece73449498085c8215ef919f5028814c140159f75e6ea5c`.

The installed log ends in parent PASS 731.887s with 17 selected cases. The 267-page log ends in parent PASS 663.984s; its test checks actual Continue-As-New, joined worker stop/new cold cache, 267 provider pages/effects, 258 entities, one generation, three projections and the unchanged deadline. These are meaningful application checks. They do not cover the two concurrency findings.

The installed group and long continuation command began before the narrow lifecycle/starter amendments. I do not treat them as blanket verification of later bytes. Final-source isolation is the 111.76s parent/63.77s child case with four succeeded runs, four nonempty snapshots, twelve projections and no legacy jobs. The 2.455s real-Temporal continued-start case tests the production starter against a controlled two-segment workflow; it is not a second collection/SQL continuation proof.

The 158.512s overlap/settlement/shipped-runtime log proves the new-owner wait path and actual initial/manual/periodic completion. The final affected race log passes its selected packages; packages printed with "no tests to run" are not coverage. The separate provider race log supplies the GitHub/IdP-focused evidence. Current-effect negatives use the actual installed guard as the exact registered session principal and roll back disposable mutations.

I ran these extra focused checks on the frozen source from `services/platform`, with race and default vet enabled:

```text
go test -race ./agentsec-worker ./orchestration -run '^(TestDiscoveryStartDelivery.*|TestDiscoveryOutboxLifecycle.*|TestDiscoveryReadinessJoins.*|TestDiscoveryRuntimeBorrowers.*|TestProductDiscoveryArtifactCache.*|TestDiscoverySchedule.*)$' -count=1 -timeout 2m
PASS: agentsec-worker 2.913s; orchestration 1.619s.

go test -race ./agentsec-worker -run '^TestDiscoveryArtifactCache' -count=1 -timeout 2m
PASS: agentsec-worker 2.486s.
```

The cache tests are named `TestDiscoveryArtifactCache`, so only the second command covers them. No new full installed suite or live-dependency scenario was run by this reviewer. No source, index, branch, ledger or manifest was changed; this report is the only written file.

## Limits remain

The historical checkpoint-40 `outcome_unknown` is still unexplained. The separate deliberate page-74 cancellation and later successful cache run do not establish its cause. Neither concurrency finding is an attribution for that incident. O(n²) cold artifact rereading remains documented scale debt.

Cloud/provider/versioned-storage IO, identity/token sources and security-tool IO in the shipped scenarios are controlled. OpenFGA is a readiness double, not authorization proof. Scoped HTTP discovery with real identity/CSRF middleware is not full `agentsec-api` root startup, which remains a mandatory P8 gate. Live Stytch, FGA enforcement, actual providers, P4C/D recovery/family work, P9 retirement, deployment and all original 728 acceptance obligations remain open as recorded.

Return both Important findings to the same implementer. Re-review the frozen fix overlay and its affected installed concurrency tests before accepting P4B.
