# M7A-84 simulation acceptance checkpoint

September 15, 2026. Local product-composed browser acceptance passed;
independent SPEC/QUALITY review approved with no findings. Publication remains pending. The original
task stays component-only. This is not live-provider or deployed release proof.

Root read the final review and verified SHA-256
`ba72809e5eabd1c2b1834fa294a198b27eff8068ee69d1e56669a0d5614f1e5c`.
Approval covers the six-file local change and selected acceptance only; full
release integration and deployed-provider gates remain open.

Original requirement: show matched evidence, proposed plan and approval points
without side effects; E2E shows authorization per proposed step. The original
M7A-83/M7A-69 dependencies are unchanged. No new microtask credit is created.

## Current local evidence

The actual built UI used the local Go API, disposable PostgreSQL, local identity
and policy-history dependencies, TLS proxy and Chrome. The selected harness
route runs after migration/seed and before unrelated runtime/recovery workloads.
It preserves API readiness. No live cloud/provider collection was run.

- Display TDD: corrected RED had three missing-result failures; GREEN passed.
  The affected UI/decoder/adapter group passed 69 tests. Typecheck and lint were
  reported exit 0; current UI source hashes matched that report when checked.
- Selected routing, witness and owned-cleanup protocol checks passed 17 tests,
  with zero failures or skips. Negative checks cover unexpected step growth,
  changed protected snapshots and a claimed simulation.
- Current production UI build completed all five stages. The browser run used
  that unchanged build.
- Actual browser attempt 3, owner session 4662, exited 0. The real simulation
  POST returned 200 and its evidence, summary, plan hash, expiry, ordered action,
  authorization and approval flag matched the rendered result. Request trace
  contained only the simulation POST and receipt GET; no execution/decision POST.

Two earlier attempts failed at setup and are retained as failures: attempt 1
omitted required policy-history configuration; attempt 2 configured its address
without starting its required readiness dependency. Both completed owned
cleanup. The successful run reused the existing local policy-history server;
it did not bypass readiness or start the unrelated runtime workload.

## Stored plan is not execution

Root corrected an overbroad all-step-count assertion after inspecting the actual
SQL. Simulation deliberately stores a terminal simulated run and proposed steps
in the same table used for executable steps. Worker claims select queued runs.

The successful witness had raw steps 0 -> 1. That exact new row belonged to the
response's simulated run and matched its returned step. The run had attempt 0,
no lease and a completed timestamp. Non-simulated run/step counts and digests,
all approval/effect counts and digests, and the target finding digest were
unchanged. The target count was 1. A real registered worker principal passed
readiness and invoked v23 claim successfully, returning no items; post-claim
snapshots and the simulation were unchanged. The result region had no action
controls. The response's side_effects value alone was not used as proof.

This ruling permits persisted simulation records, not action effects. Its risk
is a faulty scope/state predicate hiding execution; exact raw deltas, scoped
digests, the actual claim and independent review are required safeguards.

## Evidence identity

Worktree HEAD: a39e273063fc1cd1eb8b4cba117f99b070b816ff, with uncommitted changes.
Raw artifacts: `/tmp/m7a-84-snapshots.1UaGPk`.

| Artifact | SHA-256 |
| --- | --- |
| browser-3.log | e075ca18b28c6b4857dc985bfb07faa235a4781481b44c4312f17b9d04b9b4d6 |
| build.log | 99b62604b6ba253bcbcfd6dc6dbccb2998335d1e4eced17d4a751a11b3331801 |
| combined.patch, pre-review | cef72199528e777e54f6592de254dc0a646de990b1d91acb8d38df770d0cc7b1 |

Root read the actual passing witness and cleanup log, the grouped test output
and build completion, then hashed these files. The implementer's final report
and independent review must bind the final source state before publication.
