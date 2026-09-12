# Precise finalization implementation plan

> For agentic workers: use superpowers:executing-plans for inline execution,
> with test-first changes and independent review at each deliverable.

Goal: persist V3 projection receipts atomically with V3 completion and enqueue
the resulting session search work, under the existing tenant/lease authority.

Current reconciliation: the private finisher, registered51 migration, explicit
Go repository/startup routing and precise search path now exist. The unchecked
rows below preserve the original full acceptance requirements; they are not an
inventory of wholly absent code. Registered production-role tests supersede the
earlier test-only-grant mechanism for production acceptance.

`TestRuntimePrecisionRepositoryRegisteredCompletion` exercises actual FinishStage
after runner51 install, including identical replay, sandbox/source persistence,
one precise search entry and no legacy entry, retained-evidence rollback refusal
and readiness-drift refusal. Full precision actualPG races passed384.915s on
fingerprint f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd.
The registeredV3 matrix now checks full agent/session/evidence fields and
result/receipt digests, plus24 direct production-role rejection cases across
leased/succeeded states, wrong principal, expired lease, predecessor mismatch
and a rehashed malformed final item. Every rejection preserves the nine-table
atomic snapshot. Implementer actualPG races passed10.670s; independent review
found no issues and repeated both tests in22.448s. This is seeded predecessor/
finalization coverage, not fresh ingestion; the historicalV1 matrix alone was
not treated as V3 proof.

Later verification supersedes that intermediate checkpoint: owned provider proof
78940 and actual API/browser proof2555 passed, including legacy checkpoint and
historical provider preservation. Root verification65788 passed197 UI files/
1243 tests,94 release tests and the production build. The fixed50 cutover and
full11 observation integration also pass independent review and actualPG tests.
Schema51 serialized activation and live release provenance remain separate open
requirements. The source increment is not yet published to main.

Architecture: introduce a separate private SQL finisher derived from the
schema50 sandbox finisher using checked substitutions. Preserve the old
functions. Connect the repository only after a complete precision migration
can prove readiness; never route V3 to the historical finisher as a fallback.

Tech stack: Go, PostgreSQL18, PL/pgSQL, existing migration/test harness.
Spec: `2026-09-11-process-precision-design.md`.

## Constraints

V3 completion consumes projection-v3 and receipt-v3. Kernel records have source
tetragon and cannot have Exact confidence. Sandbox/source bindings remain paired;
unknown/probable records cannot acquire semantic identities. Receipt bytes are
bounded at4194304 and their SHA256 must match the successful predecessor.
Retain scope, generation, attempt, worker/token, locking and exact replay checks.
No worker grant or startup activation from a standalone fragment.

## Private SQL finisher and real PostgreSQL acceptance

Files: create `services/platform/migrations/sql/fragments/runtime_precision_completion.sql`
and `services/platform/apiserver/runtime_precision_completion_postgres_test.go`.
Consume the existing18-argument sandbox completion signature; produce
`zasp_runtime_finish_precise_session_projection` with the same types/result.

- [x] Add a PostgreSQL test using runtimeSandboxPredecessor and
  installRuntimeSandboxDraft. Before implementation, querying
  `to_regprocedure('public.zasp_runtime_finish_precise_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)')`
  must yield null. Install the new fragment and require the function to exist.
- [x] Derive from the sandbox finisher with exact occurrence checks for each
  substitution: function name, complete-v2 to complete-v3 (2 occurrences),
  projection-v2 to projection-v3 (2), receipt-v2 to receipt-v3 (1). Add an item
  rejection before assigning sandbox fields when source is not tetragon or
  confidence is exact. Preserve all inherited readiness and lease guards.
- [x] Set owner zasp_discovery_authority and revoke PUBLIC. Assert coordinator,
  projection worker and API cannot execute the fragment before a test-only grant.
- [x] Build receipt bytes with actual ProjectPrecise and EncodePreciseReceipt,
  then seed matching project-success and complete-processing rows with a live
  coordinator lease. Call the function as coordinator after the test-only grant.
  Assert persisted sandbox/source/agent/session/evidence fields, completion
  digests, projection receipt SHA256 and one sandbox search outbox row. This
  successful-path test now passes after the unpublished schema50 filter change;
  see `2026-09-11-process-precision-private-finalizer-evidence.md`. Full production
  routing is now covered through registered51 and actual Go FinishStage using
  its production role, superseding the test-only-grant acceptance mechanism.
- [x] Replay identical bytes and assert unchanged row counts/digests. Change
  receipt bytes, scope, generation, attempt, lease token or predecessor version
  separately and assert no successful completion or new session/search rows.
- [x] Supply independently rehashed Exact and non-tetragon receipts and assert
  SQL refusal with transaction rollback. Verify old V1/V2 finisher acceptance.
- [x] Run actual PostgreSQL tests with PG18 on PATH, package races, independent
  Superpowers review and a UI build. Record only observed results in the ledger.

## Registered migration and repository dispatch

Files: runtimeevent/production_pipeline_repository.go, runtimeevent precision
repository tests, migrations registration/readiness, worker runtime_config.go.

- [x] Before testing successful atomic finalization, version-filter the legacy
  search enqueue to skip both projection-v2 and projection-v3. Keep its insert
  guard restricted to project-v1/complete-v1, including cached predecessor
  trigger bodies. Under the complete precision migration identity, test a V3
  completion creates only the supported search queue entry and cannot poison
  the legacy queue or alter legacy checkpoints.
- [x] Extend sessionsearch/document.go and the runtime session search executor
  with explicit precise receipt decoding on the supported target. Existing
  DecodeReceipt rejects V3. Prove actual V3 receipt-to-document fields and
  driver writes, refusal on legacy targets, and old-byte replay compatibility.
  Update claim filtering so old consumers cannot claim unsupported V3 work.
  The search executor must read precise archives with index-v2, and accept V3
  receipts between1MiB and4MiB without widening legacy receipt limits. Assert
  target-specific checkpoint completion after the actual provider write.
- [x] Add a complete precision migration identity covering all private precision
  fragments, permissions, routing and rollback. Pin its live semantic fingerprint
  and protect historical in-flight work. Test install, drift refusal and rollback.
  Include trigger/function identity in the fingerprint, readiness drift after
  lock waits, exact rollback restoration and rollback refusal once new evidence
  is retained. Never disable triggers to make finalization tests pass.
- [x] Add repository tests that reject V3 completion when precision readiness is
  unavailable, and require the precise18-argument finisher when ready. Implement
  explicit V3 routing with original ProjectionReceipt bytes, without fallback.
- [x] Run a real database round trip through FinishStage, then the real worker
  pipeline, with tenant denial and lease-loss controls. Enable startup/claim
  selection only under the same migration readiness contract.
  Exercise terminal retry/exhaustion and a malformed final receipt item, checking
  zero partial session/receipt/outbox writes after the failed transaction.
- [ ] Run full verification and composed API/browser acceptance before publishing
  to main. Update the original task rows only when their full acceptance passes.

Historical inspection at plan creation: FinishStage special-cased complete-v2 and sent
all other successful completion versions to the V1 finisher. Schema50 derives
its V2 finisher from schema40 with checked substitutions. It retains atomic
stage/session/receipt writes and search triggers, but accepts only receipt-v2
and projection-v2. The precision finisher and readiness identity did not yet exist.

Historical independent review found the search transition dependency above. Inspected
schema50 lines307-334 skip only projection-v2 in legacy enqueue, then reject any
non-V1 insert. A V3 projection receipt would roll back the completion transaction.
runtime_session_search.go and sessionsearch/document.go also accept only V1/V2
receipts. Those required dependencies are now implemented and verified by the
registered51/worker/provider evidence described above; this paragraph records
the original defect, not the current source state.
