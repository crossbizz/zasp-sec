# Security Agent ordered multi-step implementation plan

Design: `docs/internal/2026-09-20-security-agent-ordered-multistep-design.md`

Execution model: Superpowers test-driven development, one implementation owner at a time for shared Security Agent SQL, then an independent review. The standing user instruction to continue autonomously resolves the brainstorming approval checkpoint; it does not waive any test, review, release, or external-production gate.

## Task 1: closed typed contract

Observable output: dormant generic planner context and candidate types can represent the exact `create_temporary_policy` then `run_test` sequence and server-derived targets, while release-60 runtime/repository behavior and specialized single-step contexts still reject widening.

Files:

- new `services/platform/agentsec-worker/security_agent_multistep_contract.go`
- new `services/platform/agentsec-worker/security_agent_multistep_contract_test.go`
- new `services/platform/apiserver/security_agent_multistep_contract.go`
- new `services/platform/apiserver/security_agent_multistep_contract_test.go`

The new files may call existing package-private validators, but must not edit the currently dirty release-60 planner, runtime, or repository files. This keeps the dormant contract independently reviewable and prevents accidental activation.

TDD proof: the dormant multi-step closed-schema candidate passes; duplicate/out-of-order indexes, unsupported action-target pairs, excess steps, unknown fields, and widened specialized contexts fail. Existing release-60 repository and runtime guards must still reject the candidate. No decoder, submission, dispatch, or public activation path is widened in this packet.

Batch: `go test -C services/platform -race -count=1 ./securityagent ./agentsec-worker ./apiserver` narrowed by the new test names during red/green, then the affected packages at the packet boundary.

## Task 2: release-61 dormant persistence contract

Observable output: an additive, dormant release-61 schema can persist tenant-scoped linear dependencies and immutable typed completion receipts, exposes exact readiness identity, and refuses unsafe rollback. No production registry, repository, admission, or runtime path uses it yet.

Files:

- new `services/platform/migrations/sql/0061_production_security_agent_multistep.{up,down}.sql`
- a new release-61 migration wrapper and migration tests
- new focused Postgres schema/readiness/rollback tests

Do not edit the currently dirty migration registry, CLI, repository, or release-60 files. The metadata compiler can depend on release 60 but exposes no Runner up/down method and does not insert schema version 61. Candidate SQL records only its own contract metadata. Task 3 owns production registration and predecessor ancestry rewrites.

TDD proof: exact predecessor pin, tenant keys/RLS/ACL ownership, typed receipt constraints, immutable dependency identity, readiness checksum/fingerprint, and no mutation through release-60 repositories. Down passes only for a clean unused release and refuses drift, active runs, completed runs, release-61 definitions, dependencies, receipts, and retained execution evidence.

Packet gate: migration metadata/readiness tests plus the focused Postgres schema/rollback batch.

## Task 3: restore built-in template registry coverage

Observable output: the built-in template registry and its exact ID assertion agree after the existing-test and Attack Lab templates already present in the worktree, restoring the grouped domain package baseline without changing template behavior.

Files:

- `services/platform/securityagent/templates.go`
- `services/platform/securityagent/automation_test.go`

TDD proof: reproduce `TestBuiltInTemplatesTriggerMatchersAndDeduplication`, update only the exact expected ID contract if the source registry is authoritative, then run that focused test and the full `securityagent` package. Commit the two files together so the source addition and its complete test expectation are atomic.

## Task 4: checkpoint the verified release-52-through-60 predecessor chain

Observable output: the already-verified migration/CLI predecessor files required by release 61 exist in Git as one coherent local checkpoint, so a fresh checkout can compile and test the release-61 commits. This task changes no behavior beyond the accumulated worktree state.

Files:

- the currently modified/untracked files under `services/platform/migrations` excluding already committed release-61 files
- the currently modified/untracked release-routing files under `cmd/agentsecctl`

Verification: confirm the exact staged path closure, run the full migrations package and focused release-52-through-60 CLI tests, scan staged files for secret-like material and generated process artifacts, and verify a fresh detached worktree at the checkpoint compiles/tests the migration package. Do not stage other source, evidence, UI, deployment, or ledger files.

## Task 5: release-61 production registration and ancestry

Observable output: the migrations package registers release 61 after exact release 60, exposes guarded Runner up/down methods, promotes candidate identity into shared production metadata, and keeps readiness/rollback ancestry exact. No planner, repository, worker, public API, or CLI route uses multi-step admission yet.

Files:

- release-61 migration wrapper and SQL
- migration registry/sequence tests that currently end at release 60
- new registration/Postgres rollback tests

Do not edit the currently dirty CLI files. CLI routing is deferred to the product activation packet and cannot be used as registration proof here.

TDD proof: exact 60-to-61 predecessor, registered retry, shared metadata identity, current/later drift refusal, mixed-binary release-60 fail-closed behavior, release-61 readiness after version insertion, clean down to exact release 60, and retained definition/run/dependency/receipt/evidence rollback refusal. Candidate-only metadata must not create two competing authorities.

Packet gate: full migrations package plus focused registered PostgreSQL up/retry/down/retained-evidence batch.

## Task 6: atomic ordered-plan admission

Observable output: one transaction persists the exact two-step plan, deterministic steps, dependency, first-step authorization/approval, audits, and budget linkage. Release-60 repositories remain unchanged and fail closed.

Files:

- new release-61 admission authority functions
- a release-61-specific repository route and focused Postgres tests

TDD proof: atomic rollback on invalid steps, deterministic replay and stable IDs, one first-step approval, no downstream approval before readiness, tenant isolation, and exact capability failure when release 61 is absent or mismatched.

Packet gate: focused Postgres admission batch plus dormant/release-60 repository regression tests.

## Task 7: dormant approval and receipt-gated progression authority

Observable output: approval authorizes only the current ready step, a matching immutable `temporary_policy_applied.v1` receipt advances once to the retest step, and conservative terminal outcomes block descendants. Legacy decision and expiry routes cannot bypass release-61 authority. This packet creates no effect, reservation, control, receipt, claim, or execution authority.

Files:

- release-61 SQL authority functions and readiness fingerprint
- a release-61-specific progression repository boundary
- focused Postgres progression, stop, cancellation, replay, legacy-fence, gateway-contention, and strict-response tests

TDD proof: successor waits; pending application waits; receipt consumption advances exactly once; blocked approvals cannot be decided; ready approval cannot authorize another step; approval expiry remains fail closed. Failed, stopped, cancelled, expired, unknown, and unverified predecessor outcomes never create successor work. Cross-tenant and stale-version calls fail. Concurrent progression versus approval, cancellation, budget admission, migration, device revocation, and credential rotation proves schema then Organization-first shared lock order, nonblocking gateway validation, and post-wait rechecks.

Packet gate: focused Postgres progression under race-enabled Go tests, full multistep and migrations packages, then grouped budget, temporary-policy, existing-test, approval, cancellation, policy-deployment, discovery, and runtime-data-plane legacy batches.

## Task 8A: release-61 legacy action-lane compatibility fence

Observable output: legacy claim, recovery, finish, and cleanup routes cannot select an ordered release-61 run or take an effect-first lock that inverts the ordered run/step/effect sequence. Published historical SQL stays byte-identical, legacy single-step behavior stays available, and release-61 down restores exact definitions, owners, and execute ACL order.

Files:

- release-61 promotion/demotion snapshots and guarded compatibility overrides
- readiness fingerprint coverage for live and saved function/ACL identity
- focused Postgres legacy-selection, lock-order, cleanup-state, restoration, and single-step compatibility tests

TDD proof: old claim/recovery cannot select an ordered effect; old finish/cleanup cannot mutate an ordered run; ordered transition versus legacy finish/cleanup has no inverse wait or deadlock; single-step claim, finish, cleanup, and recovery keep their prior results; exact down restoration and drift refusal pass.

Packet gate: focused compatibility and concurrency tests during implementation, then one grouped release-61 multistep, migrations, temporary-policy, approval/cancellation, and affected legacy action regression boundary. Task 8 claims remain closed until this packet is independently reviewed.

## Task 8: release-61 claim, lease recovery, and application receipt production

Observable output: only the approved dependency-satisfied temporary-policy step is claimable; one stable reservation owns its lease and recovery; the release-61 adapter applies the exact verified deployment and atomically records `temporary_policy_applied.v1` without using owner fixtures. Receipt creation and progression are replay-safe and cannot duplicate successor approval.

Files:

- release-61 claim/reservation/heartbeat/recovery SQL authority and exact readiness identity
- release-61 temporary-policy adapter and repository boundary
- focused Postgres claim, lease-loss, restart, apply, receipt, cancellation, and budget race tests

TDD proof: unapproved or dependency-blocked work is never claimable; concurrent claims produce one lease and reservation; stale workers cannot write; apply and receipt commit together; replay returns the same receipt; cancellation, budget expiry, revocation, rotation, generation drift, and lease loss before commit roll back all writes. Demotion restores exact prior function definitions and ACLs.

Prerequisite: Task 8A is complete and independently reviewed. Do not widen claims while a historical action lane can select or mutate ordered work under an incompatible lock order.

Packet gate: focused claim/application Postgres and race tests during implementation, followed once by the full multistep, migrations, budget, temporary-policy, policy-deployment, discovery, and runtime-data-plane regression groups.

## Task 9: existing-test invocation and settlement receipt production

Observable output: the approved successor claims once, invokes the pinned existing-test authority, records `existing_test_settled.v1`, and derives conservative aggregate containment from verified settlement evidence. Missing, inconclusive, stale, or mismatched evidence cannot complete the ordered run.

Files:

- release-61 existing-test claim/invocation/settlement SQL authority
- release-61 existing-test adapter and strict repository boundary
- focused Postgres invocation, settlement, restart, cancellation, and evidence-binding tests

TDD proof: exact test/version/target/safety/credential/evaluation identity is retained; one invocation survives restart without duplicate provider work; pass/fail/engine-error/cancel outcomes are conservative; stale lease and cross-tenant writes fail; receipt, step, run, reservation, and audit state commit atomically.

Packet gate: focused settlement tests during implementation, followed once by the full multistep, existing-test, artifact, linked-worker, cancellation, and migrations regression groups.

## Task 10: cleanup and terminal aggregation

Observable output: temporary policy cleanup has one durable owner and retry state; verified cleanup moves contained work to remediated, while unresolved or failed cleanup remains `needs_human`. No terminal state hides retained policy or missing cleanup evidence.

Files:

- release-61 cleanup claim, receipt, retry, and terminal aggregation authority
- cleanup adapter boundary and focused Postgres recovery tests

TDD proof: cleanup runs after every successor terminal outcome that can leave policy state; restart and lease loss do not duplicate destructive work; revoked access and partial provider failure remain visible and retryable; immutable cleanup evidence gates remediation; rollback refuses retained cleanup work or evidence.

Packet gate: focused cleanup/recovery tests during implementation, followed once by the full multistep, temporary-policy, existing-test, cancellation, reconciliation, migrations, and race groups.

## Task 11P: release-61 pricing and provider-account authority

Observable output: an administrator can create an immutable tenant-scoped pricing/account policy that approves an exact provider/model/account profile/cost unit and per-request token/cost ceilings. Private workers resolve one current policy bound to their prepared request; absent, expired, disabled, drifted, or mismatched policy fails closed before budget reservation or provider I/O.

Files:

- release61 pricing/account policy schema, admin authority, private lookup and readiness fingerprint
- strict Go repositories/configuration boundary and focused PostgreSQL tests

TDD proof: immutable versions, one active match, tenant isolation, admin-only mutation, exact provider/model/profile/unit/request digest binding, expiry/revocation, concurrency/replay, audit, RLS/ACL, rollback refusal/restoration and no public route. Policies approve ceilings only; actual provider-reported usage/cost remains mandatory.

Packet gate: focused PostgreSQL and repository tests, full migrations/multistep, budget/planner race and affected legacy groups. Independent review required before Task 11A.

## Task 11A: release-61 planning and immutable provider-result authority

Observable output: the dormant release61 worker uses the reviewed Task 11P policy to claim a tenant-scoped planning job, reserve the reviewed budget, persist immutable request intent before provider I/O, obtain or conservatively reconcile the exact two-step planner result, settle provider usage, retain stable artifacts, and call ordered admission without owner-seeded planning rows.

Files:

- release61-private planning claim/context/budget/provider SQL authority
- release61 planner repository/runtime and immutable artifact intent
- focused provider lost-ack, restart, budget, tenant, and admission tests

TDD proof: one planning lease and reservation; exact server-derived context; stable request/idempotency identity; committed intent before provider I/O; exact closed two-step result; immutable input/output artifacts; provider usage settlement before admission; no resend after unresolved non-idempotent outcome; replay and restart at every commit boundary; stale/mismatched worker refusal; cross-tenant isolation; public release60 routes remain closed.

Packet gate: focused private planner/provider PostgreSQL and process tests, then full multistep, migrations, planner/worker race, artifactstore, provider, budget, and affected legacy groups. Independent review is required before Task 11.

## Task 11: worker orchestration

Observable output: only a release-61-capable worker uses the reviewed Task 11A planning result to submit the whole validated generic plan and resumes at the current authoritative step without duplicate actions. Missing or mismatched release-61 readiness fails closed before submission.

Files:

- `services/platform/agentsec-worker/security_agent_runtime.go`
- worker repository interfaces and test authorities
- runtime, heartbeat, recovery, and combined end-to-end tests

TDD proof: two-step happy path, approval pause, lease loss, restart after dispatch, cancellation between steps, and budget exhaustion before the successor.

Packet gate: affected worker packages and the real Postgres combined path. Do not use a component-only fixture as live-provider evidence.

## Task 12: product activation and acceptance

Observable output: the public definition API allows only the reviewed generic multi-action combination, and the authenticated product journey shows ordered state and evidence without breaking single-step definitions.

Files:

- public definition validation and OpenAPI contract
- Security Agent API read models and UI only where the persisted step/dependency state needs exposure
- end-to-end/API/browser tests and authoritative ledger/progress documents

TDD proof: create, activate, trigger, approve, execute, verify, restart, cancel, and tenant-denial flows through product APIs; runnable UI build; legacy export/existing-test/Attack Lab journeys unchanged.

Final local gate: independent Superpowers review, affected tests, `npm run production:release:test`, `npm run verify`, and `npm run production:release:gate`. Push only if every mandatory local publication gate passes. Record advisory, cloud, scanner, signing, or human-observation requirements as external blocks when their actual inputs are unavailable.
