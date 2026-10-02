# Stored linked-test public proof, September 17

Component work only. M7A-21 remains disabled and component-only. No commit,
push, production promotion, cloud operation or live provider proof.
The original 728-task scope and availability counts are unchanged.

## Implemented candidate

Schema55 now projects a scoped, closed stored-proof object through the existing
registered API read. It checks persisted step/link/effect identity, saved snapshot,
proof bytes/digest and receipt before exposing safe artifact identities and
comparison checks. Storage references are hashed; raw keys, snapshots, tokens
and credentials stay private. Go and browser consumers validate the optional
contract, with backward-compatible absence. UI rendering is in progress.

Current55 fingerprint: `ac61643156258895d5e55a3ae4c8e6b47e0795a0a8bb0b4844b276bc4b56295f`.
The prior execution checkpoint's673c22 fingerprint is historical, not current.
Calibration b40def and fingerprint/release verification b287be passed before
this continuation. No subsequent SQL change has occurred.

## Evidence and fixture corrections

- Initial missing-projection RED dc4335: all four modes lacked linked public
  proof. The database fixture joined normally.
- Go consumer RED/GREEN and exact focused race evidence are in
  [the Go report](2026-09-17-existing-test-public-go-report.md). Browser decoder
  RED9ca64d rejected nine valid fixtures before implementation; GREEN1b6185
  passed all32 cases. These are consumer tests, not live-product acceptance.
- First registered SQL run in this continuation, a40cda, failed all four modes
  at a fixture assumption: the protocol negative test expected a grant left by
  private dispatch. Registered dispatch has no such grant. The helper now
  explicitly adds the unwanted permission, proves55000 rejection, revokes it,
  and then runs positive registered protocol selection. Production ACLs unchanged.
- Next run9c382a failed settlement claims because the separately composed
  reconciliation-client acceptance intentionally released the same link with a
  300-second delay. Both tests passed individually but conflicted when combined.
  Ruling: run SQL settlement and client delay acceptance separately in this batch.
  This preserves both checks; full runtime/browser composition remains required.
- Corrected owned run710f4f passed `TestSecurityAgentExistingTestPublicProofPostgres`
  in52.80s, all four run/rerun supervised/autonomous cases. Real registered
  preparation/dispatch, completion and settlement feed the registered API read,
  and the actual Go run-context decoder accepts pending and settled projections.
  Scope denial, no mutation and receipt/proof/snapshot tampering are checked.

Run710f4f used `/private/tmp/zasp-public-proof-api-green-r3` in an owned offline
Docker container, PostgreSQL image
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`,
`--pull=never --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,mode=1777
--user postgres`, readonly repository/Node mounts, and exact test selection.
`ZASP_RECONCILE_CLIENT_BINARY` was omitted for this SQL-settlement invocation.
Owned PostgreSQL pid30 joined with both exit codes0. No host database was started
by this continuation. The prior subagent's accidental host fixture is disclosed
separately in its Go report.

## Still in this batch

Extended verification passed in owned grouped run ae04b7: normal proof54.23s
(four modes) and stopped-parent proof16.33s (one supervised run mode, selected
by the existing stopped fixture). Tests compare exact before/after artifact
identities using independent Go SHA256, deny worker API reads, and verify history
after credential revocation. Both owned database processes joined with exit0.
Binary `/private/tmp/zasp-public-proof-api-green-r4`; same offline mounts and
no reconciliation-client delay child. This is five cases, not eight.

Independent scoped SQL/Go review found no Critical/Important findings and
confirmed the identity correction plus new artifact/history/role coverage.
It leaves UI/browser and live readiness open. Late-completion recovery passed
7e00f7 in15.56s (one autonomous run case) using api-green-r5. The registered
callback updates the invocation journal after unknown-outcome settlement; the
subsequent API read still exposes the saved inconclusive proof. Owned PostgreSQL
pid27 joined with exit0. The settled read also repeats role, scope, artifact,
history and tamper checks. This is controlled callback proof, not live-provider
execution. Ledger validation d5b631 confirms728 rows:534 production-available,
133 component-only,61 blocked/external,0 missing.

Composed worker-to-public-read run54b217 passed51.10s, all four modes, with
api-green-r6 and public-proof-worker-r1. The actual Node product artifact producer
and registered Go comparison/reconciliation child feed the public API read;
the child succeeds in each mode and the helper checks the resulting stored proof.
Controlled engine responses and an in-memory versioned evidence driver remain
fixture dependencies. This does not prove live storage, a real target invocation,
browser execution or production discovery. Owned PostgreSQL pid28 joined normally.

Fresh grouped Go consumer/action race933d84 passed2.471s with explicit unit
selection and `-skip Postgres`. Fresh owned compiled-fingerprint/release bd8af7
passed4.23s/9.20s. OpenAPI generation check and contract tests aff59e passed40/40.
No broad release/advisory clearance is inferred from those narrow gates.
Final OpenAPI lint738c62 validates both public and internal-health documents.

Composed cancellation projection fa99e1 passed37.17s, four modes using api-green-r7
and public-proof-worker-r1. The existing registered stopped-work reconciliation
and cancellation classifications feed the same public-read verifier, covering
confirmed cancellation before/after partial work and unknown outcome. Owned
PostgreSQL pid26 joined normally. This is distinct from the one completed-test
stopped-parent case above; both preserve the parent's independently stopped state.
The small wrapper/read-hook delta awaits the final batch review.

Rendering and scoped history integration are implemented. The proof links require
Red Team read permission and preserve the active scope; selected URLs load the
exact run through the scoped client, including absent-list runs. Selection/scope
changes abort stale reads and hide old details. See [rendering evidence](2026-09-17-existing-test-proof-ui-report.md)
and [history RED/GREEN evidence](2026-09-17-existing-test-proof-history-report.md).
The grouped affected UI suite passes166/166, typecheck and scoped lint pass.
Main consumer regression ecb4d2 passes72/72 across the linked-proof and existing
Security Agent decoders. These are real React/client tests with controlled API
responses, not a mounted browser/database workflow.

UI build and compiled-production-import guard ccd66e pass (7 client/8 server
chunks). Standalone loopback HTTP check8c22cc returns200 for root and7 compiled
assets. This proves shell/asset runnability only, not authenticated product use.
Combined UI/history and final cancellation-hook independent review found no
Critical/Important findings and judged the bounded batch spec-compliant.
One Minor coverage opportunity remains: explicit pending-read API-instance and
query-generation changes, beyond the passing selection/scope/unmount cases.
Carry it into whole-feature review; it is not silently counted as verified.

The standalone process (tool session80147) was stopped after the HTTP check,
exit130 from the requested interrupt. No test/server process from this continuation
is intentionally left running. Final binary identities:

- api-green-r7: `df686ae98d9865b2ab3fcf87262ef1e8a6373e8e6e29fdd5e3560467c8370938`.
- public-proof-worker-r1: `3e5a9dcacb8f634e0c671af665f9eb116a5f528b0c047196acd23ebb9bd33c99`.

No source modifications followed the UI build except documentation. Preserve the
batch evidence; rerun covering checks if its code changes during review.

Task1 projection/consumer/UI/history batch is complete at component acceptance,
uncommitted and unshipped. Task2 remains incomplete.

Actual composed browser workflow, whole-feature review and exact push
candidate release gates remain open. Provider/cluster/load/advisory gates remain
external and must never be replaced by these fixtures.
