# Existing-test durable settlement implementation plan

> Use Superpowers executing-plans inline, TDD and independent review, with
> verification grouped by this feature batch. The user's standing authorization
> allows implementation decisions without another approval pause.

**Goal:** Record immutable verification results and atomically settle linked
Security Agent steps/effects/runs, including crash recovery and lost responses.

**Architecture:** The registered Security Agent worker owns a separate scoped
reconciliation lease. Settlement compares its previously read database snapshot
with current locked authority, validates the verifier result against persisted
attempt/journal receipts, and records one immutable outcome/audit. Artifact and
native evaluation checks remain in the real Go verifier; SQL independently
enforces receipt/journal association and allowed transitions.

**Tech stack:** PostgreSQL55 candidate migration, Go/pgx, current artifactstore.
**Spec:** Original v1.5 M7A-21 and
`2026-09-16-security-agent-existing-test-design.md` plus the authority and
implementation plan in this directory; this addendum resolves the settlement
contract, not scope.

## Constraints

- All728 original tasks stay in scope; M7A-21 remains component-only/disabled.
- No fixture or component result is live provider/deployment evidence.
- Use owned offline PostgreSQL only. No host database startup or mutation.
- Exact registered principal and compiled checksum/fingerprint on every call.
- No target execution grant, no replayed target invocation from reconciliation.
- No push before full release verification and runnable UI checks.
- Preserve unrelated dirty-worktree changes.

## Settlement contract

Create `services/platform/migrations/sql/fragments/security_agent_existing_test_settlement.sql`
and append it after reconciliation in `security_agent_existing_tests_release.go`.
Add guarded function with this argument order:

```sql
zasp_production_security_agent_existing_tests_reconcile_settle(
 o text,w text,e text,r text,s text,worker_value text,lease_value bytea,
 version_value bigint,expected_snapshot jsonb,proof_bytes bytea,
 expected_checksum text,expected_fingerprint text) RETURNS jsonb
```

`proof_bytes` is the exact UTF-8 JSON from the Go verifier. Reject duplicate keys,
unexpected shape and payloads over64KiB before casting. Persist SHA256 of those
exact bytes, never compare that hash with PostgreSQL's `jsonb::text` encoding.
Snapshot equality uses JSONB equality, not a cross-encoder hash.

Lock organization admission, parent and link using existing reconciliation lock
order. Check exact step action/input and pending effect association. Lock linked
after/baseline test runs with NOWAIT before taking the fresh snapshot, preventing
late adapter completion from changing its journal during settlement. Refuse
changed snapshots without any step/effect/audit mutation.

Permit ordinary queued/live leased work only to remain pending. An expired
leased run with an invocation journal can otherwise stay stuck forever after a
worker crash. Under its run lock, classify that execution as failed/unknown and
retain the journal and durable cancellation uncertainty. Never infer remediation
from a missing finish artifact or resend an uncertain request. A late journal
completion does not erase a stored outcome_unknown classification.

Allowed verifier results include remediated/test_condition_changed,
needs_human/test_condition_persists, needs_human/test_baseline_unavailable,
inconclusive/test_evaluation_inconclusive, inconclusive/test_evidence_unavailable,
and explicit unknown execution reasons. Definitive pre-execution rejection is
Failed; confirmed cancellation is Cancelled, not an inconclusive alias. A
complete passing test without a comparable baseline has a succeeded test step
and a needs_human parent. Valid failing test evidence also represents completed
test execution, with needs_human parent because the condition persists. Engine
errors and unknown evidence produce an inconclusive step. Remediation requires
complete failed baseline, complete passing after-run, exact attempt/artifact
receipts, no unknown outcome, all current categories protected and at least one
prior unsafe category. Compare full target and actual credential-version tuples
between before/after journals. Check per-category proof flags/HTTP status and
curated check identities. The registered Go verifier must already have checked
the retrieved native/evaluation identity, image and assertion digests.

Record proof and receipt on the link; clear its active lease, increment its
version and mark it settled. Keep separate immutable original worker/token-hash/
claim-version association for exact lost-ack replay. A repeated identical request
returns the saved receipt even after lease expiry; changed token/version/proof
must refuse. Ordinary Claim never returns settled links.

Update running/verifying parent state from the accepted outcome, clearing parent
lease fields when terminalizing. Preserve already cancelled/failed/inconclusive/
needs_human parents and cancelled steps. Do not reuse the old generic verify
function, which blindly maps outcomes to verified/succeeded. Keep cancelled
outcomes distinct from verified effects. Emit one deterministic test_reconciled
audit event. After all writes/audit waits, recheck compiled authority and original
reconciliation deadline; expired work must roll back all changes.

## Batch execution

- [x] Add `apiserver/security_agent_existing_test_settlement_postgres_test.go`
  and hook the real completed-attempt fixture. Owned actual Node RED58abb9
  fails12.89s with missing settlement function42883. Database joined normally.
  Review corrected the initial test's step-state expectation to preserve
  succeeded test execution independently of a needs_human parent. SQL
  implementation was absent at RED. The candidate now has grouped acceptance
  evidence in `2026-09-17-existing-test-settlement-checkpoint.md`.
- [ ] Implement migration contract above, register the fragment and calibrate
  its fingerprint only against the owned database. Implement all outcomes,
  including expired uncertain execution, before calling settlement complete.
- [ ] Prove changed lease/version/snapshot/proof refusal; exact lost-ack replay;
  one outcome/audit; step/effect/parent persistence; no later target resend.
  Example atomic assertion:

  ```sql
  SELECT l.reconcile_state='settled' AND r.state=$6
    AND s.state=$7 AND e.state=$8
  FROM zasp_security_agent_test_links l
  JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
  JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
  JOIN zasp_security_agent_effects e USING(organization_id,workspace_id,environment_id,run_id,step_id)
  WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5);
  ```

  For a validated pass with no baseline, bind parent needs_human, step succeeded,
  effect succeeded. For engine/unknown execution, bind parent/step inconclusive
  and effect unknown_outcome. Never equate the parent outcome with step success.
- [ ] Add observed lock-wait cases for release drift, reconciliation expiry,
  late completion and stopped-parent races. Run the same registered principal
  and refusal checks for all execution modes.
- [x] Extend worker client with Settle using exact proof bytes, preserve the
  source snapshot in decoded evidence, and test receipt identity/replay.
  Grouped worker race7bb3a9 and registered owned client97f197/c021d9 pass.
  Registered settlement covers unavailable/unknown evidence, not successful
  artifact retrieval, remediation or process-restart persistence.
- [ ] Compose polling with heartbeat, snapshot classification, exact-version
  artifact retrieval/comparison, release of pending work and Settle. Unknown
  must be checked before comparison. Test process restart and lost responses.
- [ ] Independently review the batch. Run grouped owned settlement/completion/
  reconciliation/fingerprint/rollback tests, worker race and ledger checks.
  Update evidence once for the batch. Full UI/release gates precede any push.

Independent design review identified and corrected terminal-only recovery,
lost-ack replay, cancelled-step preservation and proof-encoding gaps. The SQL
candidate and grouped acceptance are recorded in the settlement checkpoint.
Unchecked items above remain batch completion gates: version exhaustion,
stopped queued work, missing outcome acceptance and client/worker composition
prevent claiming settlement complete.
