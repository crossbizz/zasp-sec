# Linked-test public proof design

This implements the existing Batch C action projection and Batch D user workflow,
without changing the original728 scope. Standing user authorization selects this
design and replaces routine approval pauses. M7A-21 stays component-only/disabled.

Extend the existing opt-in action-details response, not a separate unbound lookup.
`SecurityAgentActionDetail.existing_test` is optional and omitted before dispatch,
for non-test actions, and on older servers. When present it is a closed object:

```ts
type ExistingTestDetail = {
  definition_id: string; definition_version: number; test_run_id: string;
  state: "pending" | "settled";
  cancellation_outcome: null | "cancelled_before_execution" | "cancelled_after_partial_execution" | "outcome_unknown";
  verification: null | {
    outcome: "remediated" | "needs_human" | "inconclusive" | "failed" | "cancelled";
    reason: "test_condition_changed" | "test_baseline_unavailable" | "test_condition_persists" | "test_outcome_unknown" | "test_evidence_unavailable" | "test_evaluation_inconclusive" | "test_run_failed" | "test_run_cancelled";
    proof_digest: string;
    before: TestAttemptProof | null; after: TestAttemptProof | null;
    checks: TestCheckChange[];
  };
};
type TestAttemptProof = {
  run_id: string; attempt: number; input_digest: string;
  input_artifact: TestArtifactIdentity; output_artifact: TestArtifactIdentity;
};
type TestArtifactIdentity = {
  reference_digest: string; version_id: string; sha256: string; size_bytes: number;
};
type TestCheckChange = {
  category: string; check_id: string; prompt_digest: string; assertion_digest: string;
  before_protected: boolean; after_protected: boolean;
  before_http_status: number; after_http_status: number;
};
```

All IDs are canonical ProductIDs; definition versions1..1000000, attempts1..5.
Digests are nonzero lowercase64-hex except proof_digest, which is sha256: plus
64-hex and equals the displayed effect result digest. Artifact reference_digest
is SHA256 of the exact stored reference bytes; no raw S3 URI, key or bucket is
public in this projection. Version IDs use the existing bounded1..512 printable
no-whitespace contract; input size1..65536, output size1..16777216. Version/digest
identities are evidence metadata, never new storage reads or download authority.

The SQL private projection reads a fully scoped link only after the existing
registered API run read succeeds. It binds definition/version to displayed
arguments; displayed outcome_id to the persisted effect outcome_id; link input digest to the exact
persisted step; settlement receipt to run/step/effect and proof digest. Settled
proof bytes must hash to the effect/receipt digest and decode to stored proof.
Validate proof against its saved snapshot using the existing private proof
validator, preserving historical evidence rather than re-resolving today's target.
Before/after IDs come from saved baseline and linked run respectively.

Review correction: effect outcome_id is a separate canonical security_agent_effect
ID, not the linked Red Team run ID. SQL binds them through the exact scoped
link/step/effect association. Go/browser must not invent equality between IDs.

Pending includes leased reconciliation but never verification. Settled requires
verification; no partially settled public envelope. Remediated requires distinct
before/after runs and1..6 unique allowed checks, at least one unsafe before check,
all protected after, both HTTP200, exact curated check IDs and nonzero digests.
Other outcomes expose no checks. Needs-human requires after; inconclusive/failed/
cancelled may have null attempts. Outcome/reason pairs must match the existing
settlement table; outcome_unknown cancellation never becomes remediated.
Do not require parent final state to equal proof outcome: stopped parents retain
their own state. Explain stored test result separately in the UI.

SQL rebuilds every public nested object from an allowlist. Go and TypeScript
validate exact keys, presence/null rules, bounds and cross-field association.
Go validates both DB envelopes and public structs before handler header filtering.
Absence remains backward-compatible; a malformed present object fails closed.
No proof_hex, worker/token/generation, raw snapshot, endpoint, credential metadata,
provider text or raw responses reach the UI. Capability enablement is unchanged.

The UI shows pending versus settled, safe reason labels, before/after run IDs,
attempts and immutable artifact identities, and per-check protected changes.
Confirmed partial cancellation must say prior work was not undone. Unknown means
unconfirmed execution, not cancellation. Existing scoped navigation is extended
only with real Red Team run routes and reload handling; IDs alone do not grant
cross-tenant access. Full composed browser acceptance follows this projection.

Rejected alternatives: returning raw reconcile_settlement leaks private authority;
deriving improvement in the browser loses the persisted comparison contract;
adding a separate endpoint duplicates scope and version negotiation.
