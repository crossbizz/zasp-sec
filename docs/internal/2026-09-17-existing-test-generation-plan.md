# Existing-test claim generation implementation plan

> For agentic workers: use Superpowers executing-plans, TDD and independent
> requesting-code-review. Execute as one ownership-protocol batch under the
> user's standing autonomous authorization. Do not ship partial signatures.

Goal: remove reconciliation counter stranding while preserving stale ownership
and immutable settlement replay fences. All original728 tasks remain in scope.

Architecture: SQL assigns a fresh UUID generation on every successful claim.
Every guarded operation binds that generation alongside scope, parent, step,
worker, token, bounded version and original live deadline. At the counter limit,
release/settlement retain the maximum version; the next claim cycles to1 and
always generates a new generation, including when the caller reuses its token.

Tech stack: PostgreSQL guarded functions, pgx, Go worker and owned Docker tests.
Spec: the ownership contract and implementation steps below are the design for
this bounded protocol change; the existing settlement and cancellation plans
retain their other requirements.

## Verified failure and decision

TestSecurityAgentExistingTestReconcileVersionBoundaryPostgres exercises a real
registered SQL claim at version999999, then requires release, a fresh claim and
stale-claim refusal. Owned session5837 exited1 (834f7f), all four execution modes
failed with22023: SQL issued1000000 but release refused it. The enclosing batch
check also found no claimable links after the four failures. DB joined normally.
This is a product defect reproduction, not a passing acceptance result.

Independent design review recommends a DB-generated generation. Raising the cap
postpones the same defect. Stopping issuance earlier strands work. Cycling only
the counter permits an old worker/token/version tuple to become valid again.
An explicit exhausted terminal state is possible but would abandon otherwise
valid reconciliation work; generation fencing preserves continued processing.

## Protocol contract

- Add `reconcile_generation uuid NOT NULL DEFAULT gen_random_uuid()` to links.
  Every successful claim overwrites it with a fresh DB-generated UUID. Failed
  claims roll back generation changes. Heartbeat never changes it.
- Claim arguments remain unchanged. Each claim receipt adds `generation`, a
  canonical UUID string. The worker stores it immutably in existingTestClaim.
- Lock/evidence/cancel_stopped/heartbeat/release/settle add a UUID argument
  immediately after the claimed version, before operation-specific data/pins.
  The private lock requires exact generation equality in its scoped live-lease
  lookup. All callers pass it; no compatibility overload bypasses this check.
- Claim selects eligible pending or expired links at every valid counter value.
  Its update uses `CASE WHEN reconcile_version=1000000 THEN 1 ELSE
  reconcile_version+1 END` and `gen_random_uuid()` in the same locked update.
- Release/settlement accept versions1..1000000. Their resulting version is
  `LEAST(version_value+1,1000000)`. Release clears worker/token/expiry as before.
  Generation can remain on pending/settled rows; state and ownership still fence
  them. The next successful claim always replaces it.
- Evidence envelopes and heartbeat/release/settlement receipts carry generation.
  Go strict decoders reject missing/malformed/mismatched generation.
- Settlement records claim_generation inside immutable settlement metadata.
  Exact replay matches generation in addition to all existing identity, token,
  version, snapshot and proof-byte checks. Expired exact replay remains valid;
  another generation cannot replay it. Saved Go requests retain the generation.
- Unrelated test-run, definition and API version bounds do not change.

## Coordinated implementation batch

- [x] Reproduce the current issued-claim release failure with owned SQL.
- [x] Extend the boundary test's fresh claim to reuse the same worker/token.
  Require a different generation, stale evidence/heartbeat/release/cancellation/
  settlement refusal, fresh evidence success and release the fresh claim so the
  enclosing normal batch-limit assertion still sees pending links.
- [x] Add expired-reclaim generation change and max-version settlement/exact
  lost-ack replay acceptance, including mismatched generation refusal.
- [x] Modify migrations/sql/fragments/security_agent_existing_test_reconcile.sql
  and security_agent_existing_test_settlement.sql using the contract above.
  Update ownership, revoke/grant signatures and rollback cleanup together.
  Search all references to each changed function name before compiling.
- [x] Update agentsec-worker/security_agent_test_client.go claim parsing/args,
  security_agent_test_snapshot.go envelope validation and
  security_agent_test_settlement_client.go saved request/receipt validation.
  Change expected post-release/settle version to the saturating expression only;
  retain all existing scope, proof, state and deadline checks.
- [x] Update the actual registered child, query-boundary tests and all owned
  invocation sites to pass generation. Keep test expectations hand-derived:
 999999 claim ->1000000; max release ->1000000; next claim ->1/new generation.
- [x] Calibrate changed migration fingerprint only in an owned offline database,
  update the compiled pin, then rebuild matching API/worker test binaries.
  Adapter binary was not invoked by this batch and remains stale; rebuild it
  before any adapter-child acceptance that uses the new pin.
- [x] Run grouped boundary/pending/cancellation/settlement/artifact/fingerprint/
  release-rollback acceptance and worker/migration race suites. Independent
  review must audit every guarded call and replay path for generation binding.
- [x] Update authoritative ledgers with terminal evidence. Keep M7A-21
  component-only/disabled until production mounting and live gates are met.
  Full release and runnable-UI gates precede any commit/push to main.

## Evidence limits

The original boundary regression was red. Generation migration/client changes
now exist as an unshipped candidate; evidence below supersedes that initial state.
No completion, production promotion or push.
Leased cancellation-to-settlement composition, production scheduling/restart and
live provider/engine/storage acceptance remain required beyond this batch.

## Candidate implementation evidence

SQL generation fencing is implemented in reconcile.sql and settlement.sql.
The Go claim, snapshot, guarded calls and immutable settlement request/receipt
carry generation. Counter saturation/cycling leaves unrelated product version
bounds unchanged. Catalog-derived fingerprint and rollback enumeration cover
the new UUID column and function signatures without a compatibility overload.

Local generation RED e63777 reproduced the old client's rejection of the new
maximum-version claim. Focused existing-test tests e200c8 then passed2.499s.
Owned calibration20accc observed fingerprint
`d64a65660783c429fb046bb7efb913127948492405fdd74216f943c10a6cdf11`;
the compiled pin was updated from that result. Owned session48778 ended exit0
(0a4242/ddf63f): direct cancellation28.44s, stopped leased/retryable28.26s,
normal reconciliation16.65s, boundary rollover19.60s, fingerprint3.15s and
release/rollback8.32s. Four-mode tests include same-worker/token reuse with a
fresh generation, old-generation refusals, and successful fresh release/read.

Independent source review found no Critical/Important defect but required real
SQL maximum settlement/expired replay and generation-specific decoder failures.
The latter now cover six paths with valid controls and missing/null/zero/
malformed/uppercase/alias/duplicate generation. Initial snapshot positive-control
failure8a9b07 was caused by reusing a map with unrelated fields; clearing that
test map fixed it. Grouped worker/actual Node race644861 passed9.842s and
migration race654885 passed5.095s. Re-review found no new findings in the fixes.

Composition session92219 passed WorkerFinish41.83s, registered normal
reconciliation19.60s and stopped queued20.03s with real client SQL, controlled
artifact storage and actual Node-produced bytes. Its later direct SQL cases
were misconfigured: the registered child had already settled the work before
the SQL test could claim it. Session39966 similarly ended exit1 (dabf64).
Neither enclosing group is a passing result. No product code was changed for
this harness conflict. Direct SQL settlement must run with the child disabled;
corrected session50482 is currently live, not acceptance evidence yet.

The rebuilt max-settlement test requires claim1000000, saturated persistence,
matching generation and exact replay after observed database-clock expiry of
the original settlement lease. Wrong-generation replay is refused. Independent
review accepted the assertions conditional on that fresh owned run.

Corrected direct SQL session50482 ended exit0 (e67b5a/1821c3/6884d2):
normal settlement46.76s, maximum-version settlement with expired exact replay
53.71s, uncertain recovery12.60s. Normal and maximum each passed all four modes;
recovery exercised its intended autonomous uncertain case. Every owned database
joined normally. Session92219 later ended exit1 (7f5abf), as expected from its
documented double-settlement harness configuration; its passing component cases
are not presented as a passing enclosing group.

The rebuilt maximum test now provides real SQL evidence for the review gap:
issued version1000000 settles atomically without overflow, exact proof replay
survives observed original-deadline expiry, and another generation cannot replay
the receipt. Generation-specific decoder controls and corruptions passed in
worker race644861. Independent re-review found no new actionable findings.

UI production build88795a exited0 and generated dist/standalone. This is build
evidence only, not a browser/user-flow or live deployment acceptance. Full release
gates, adapter-child refresh when needed, leased cancellation-to-settlement
composition and production tenant scheduling/restart remain open. No commit,
push or production-availability promotion. The original728 ledger still validates.
