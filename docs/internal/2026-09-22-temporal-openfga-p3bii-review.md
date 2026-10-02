### Spec Compliance

SPEC: Issues found. Delayed or restarted compensation can become permanently unfinishable after its five-minute signing marker expires. This misses the required reusable recovery behavior; see Important issue 1.

Review scope: all 38 changed source/test files in `p3bii-cont3-full-scoped.diff`, against the original `p3bii-baseline`, read in passes without reducing scope. This is the P3B-II domain-executor gate, not whole-branch or production acceptance. Source references below are relative to `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

Cannot verify from this packet: actual Temporal workflow/Activity registration and cancellation orchestration belong to P3C; active OpenFGA model/revision enforcement belongs to P7; deployed provider, gateway enforcement and cleanup proof belong to P10. These remain gates, not defects assigned to this task. The implementation report keeps that distinction at `docs/internal/2026-09-22-temporal-openfga-p3bii-report.md:276`. The controller should retain P3B-I's supported-predecessor installation evidence alongside this packet; these fresh-fixture tests alone are not a newly observed retained61/66 installation matrix.

### Strengths

- Stable product identity and committed send permission are explicit in `services/platform/migrations/sql/0068_production_temporal_executor.effects.sql:16` and `:75`. The adapter also rejects an unresolved category start, binds the saved target/request/effect, and permits only an existing invocation's late completion (`0068_production_temporal_executor.linked.sql:168`). No retry-attempt identity or fabricated lease is needed.
- The production path is present. `services/platform/red-team-adapter/production_routing.go:24` selects the verified68 journal and retains separate standalone/legacy linked routes; `services/platform/agentsec-worker/security_agent_temporal_runner.go:169` calls the real effect runner. `workers/redteam-node/runner.mjs:51` emits the separate effect header. Repository input/output readback and native settlement checks are real code, not an unused constructor (`services/platform/apiserver/security_agent_temporal_linked_repository.go:57`, `:148`).
- Narrow authority. The additive migration consumes validated67, saves predecessor definitions, binds independent post-transition fingerprints and registers exact executor/compensation principals (`services/platform/migrations/production_temporal_executor.go:69`; `services/platform/migrations/sql/0068_production_temporal_executor.up.sql:30`, `:53`, `:304`). Shared admission still uses the organization lock and public budgets (`0068_production_temporal_executor.up.sql:93`, `:155`).
- Planning and terminal evidence stay separate. Unknown usage is not fabricated as zero; late known usage has its own immutable association and exactly-once charge (`services/platform/migrations/sql/0068_production_temporal_executor.planning.sql:72`; `0068_production_temporal_executor.late_usage.sql:16`, `:81`). Public terminal reads validate saved settlement/stop/cleanup evidence (`0068_production_temporal_executor.settlement.sql:44`, `:134`; `0068_production_temporal_executor.cleanup.sql:128`).
- The tests exercise real disposable PostgreSQL principals, committed intent before controlled HTTPS calls, lost acknowledgements, wrong-scope compensation and actual artifact-store operations. Relevant examples: `services/platform/apiserver/security_agent_temporal_executor_postgres_test.go:698`, `:1564`; `services/platform/redteamadapter/temporal_owned_https_test.go:77`; `services/platform/agentsec-worker/security_agent_temporal_planning_test.go:65`. Their controlled-provider limits are stated honestly.

### Issues

#### Critical (Must Fix)

None found in this scoped review.

#### Important (Should Fix)

1. **Cleanup cannot recover after its signed marker expires.** `services/platform/migrations/sql/0068_production_temporal_executor.cleanup.sql:61`, `:98`, `:101`, `:105`, `:110`, and `services/platform/migrations/sql/0068_production_temporal_executor.delivery.sql:37`.

   A valid compensation call stores a removal marker with exactly five minutes of validity. If the worker restarts or delivery is delayed past that point, `delivery` rejects every unacknowledged attempt. Reusing the original source fails the expiry check; supplying a freshly signed source fails the immutable replay comparison because the existing target is already `stored`. `prepare` only creates targets when the cleanup row is absent, and `unknown` only changes its state. Neither repairs this dead end.

   The narrower case also fails: store, read back and acknowledge the replacement bundle while the marker is valid, then restart before `cleanup complete`. Completion always calls `cleanup_acks(..., true)`, which rejects the now-expired marker even though the durable acknowledgement and signed replacement remain intact. The retained composition helper explicitly gives that replacement a separate lifetime, up to 24 hours (`services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql:10`), so the five-minute marker expiry is not evidence that the acknowledged cleanup failed.

   Add scoped recovery for both cases. An already-acknowledged cleanup should reconcile its retained evidence without requiring a still-live signing window. An unfinished cleanup needs a narrowly authorized renewal/reconciliation transition that preserves the original source and delivery evidence, keeps the same product effect identity, and cannot remove another run's resources. Do not merely accept expired signatures or overwrite historical proof. Add focused PostgreSQL cases for restart after source storage, restart after acknowledgement, requester deactivation, unchanged pending/unknown reporting until proof exists, and replay without duplicate delivery.

#### Minor (Nice to Have)

- Existing validation noise, outside this delta: `services/platform/apiserver/security_agent_attack_lab_settlement_postgres_test.go:330` still fails vet with `append with no values`, as recorded in `p3bii-cont2-vet.log:3`. The final SQL suite uses `-vet=off`; it is not clean-vet evidence. The retained runner negative cases also print expected version-mismatch diagnostics (`p3bii-runner-green.log:9`, `:30`). Neither is a newly introduced P3B-II failure.

### Checks and evidence

- Read all three task briefs and every continuation of the implementation report. Read the complete 6,437-line cumulative diff. No git commands, tests, subagents, source edits or activation were used for this review.
- Independently compared all 38 current after-hashes with the full manifest: zero mismatches. Diff SHA256 is `91b4d964a89514ff33633c3ca7ce752590518396b18f915b56ff44210f6d6713`; implementation-report SHA256 is `6feb88f833b248a98fd88144e8dae9371c4060c041dbbeea280693596312b5a8`. The manifest reports 150 historical SQL files unchanged; no historical SQL path appears in the scoped delta.
- Read retained final results, without rerunning suites: `p3bii-cont3-final-postgres.log:393` reports PASS, 1233.065s at `:394`; all 22 top-level tests passed. Component package results are at `p3bii-cont3-components.log:237`, `:348`, `:373`, `:509`. Owned-only skips there are separate from the nested executions in the PostgreSQL run; the Go/Node contract cases also skipped at `:73` and `:76`. The retained Node run reports 15 passing tests in `p3bii-protocol-node-green.log`. Retained55 routing passed at `p3bii-cont3-retained55-routing.log:33`, 25.435s at `:34`.
- Named outside-diff risk, inherited lock/current-authority behavior: checked complete `application_lock`/`application_current` in `0061_production_security_agent_multistep.application.sql:3`, `:41`, `test_lock`/`test_current` in `0061_production_security_agent_multistep.test.sql:2`, `:13`, and `transition_current` in `0061_production_security_agent_multistep.progression.sql:116`. The extracted68 current-plan helper keeps immutable plan, budget, usage and live requester/approval checks; the existing locks cover the consequential SQL transitions.
- Named outside-diff risk, cleanup lifetime/recovery: checked retained `cleanup_targets` at `0061_production_security_agent_multistep.cleanup.sql:215` and the composition/freshness helpers at `0061_production_security_agent_multistep.cleanup_deployment.sql:1`, `:62`. These do not renew the new68 marker or bypass its completion-time expiry check.
- Named outside-diff risk, receipt-decoder contract: checked `services/platform/redteamadapter/postgres_journal.go:165`, reused by `decodeTemporalJournalReceipt`, and the surrounding `InvokeJournaled` body because its diff hunks stopped mid-function. Exact target/request/comparison/credential-version checks remain; the new effect identity is checked before send.

### Assessment

QUALITY: Needs fixes.

The authority split, one-send journals and evidence binding are well built, with substantial retained regression coverage. Fix the cleanup recovery dead end before accepting P3B-II; then rerun only the affected recovery and readiness groups against a frozen source snapshot.
