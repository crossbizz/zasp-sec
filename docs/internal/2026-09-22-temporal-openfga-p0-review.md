# P0 review: inventory gap addressed

2026-09-22. Independent, read-only review of
`/tmp/zasp-temporal-openfga-p0-review.z3VtsN/p0-only.patch`, against the approved
Temporal/OpenFGA design and execution plan. This report is the only file I changed.

Final SPEC: PASS. Final QUALITY: PASS.

Scoped re-review: ADDRESSED. No new issue in the changed text. The original
finding and its first-pass verdict follow below as review history.

Initial SPEC: NEEDS CHANGES. Initial QUALITY: NEEDS CHANGES.

One P2 finding; no P0 or P1 findings. The crosswalk and evidence boundaries pass
the substantive checks below. The retirement inventory needs one bounded addition
before its family coverage is complete.

## The missing caller chain

[P2] (confidence: 9/10) `2026-09-22-temporal-openfga-retirement.tsv:30`:
the deployment row mentions "security-agent/action/policy workers", but none of
the 36 rows traces the active policy-deployment processor, its SQL authority or
its retain-versus-replace decision. This matters because the crosswalk already
maps M6-18 to P3/P4/P8 and requires signed policy deployment across Activities.
P4 cannot make that decision from the recorded caller chains.

I checked the source:

- `services/platform/agentsec-worker/production_runtime.go:215` selects
  `case workerModePolicyDeployment:`; line 220 returns
  `composePolicyDeploymentWorkerRuntime(config, database, privateKey)`.
- A separate lease processor. In
  `services/platform/agentsec-worker/policy_deployment_runtime.go:79`, it calls
  `ClaimPolicyDeployments`; its heartbeat loop calls
  `HeartbeatPolicyDeployment`, and its apply path signs, stores, reads back,
  verifies and finishes the gateway envelope. This is active custom durable
  work, not the release61 deployment repository named elsewhere in the inventory.
- `services/platform/apiserver/policy_deployment_repository.go:17` contains
  `SELECT zasp_policy_deployment_claim($1,$2,$3,$4)`; lines 18-21 name the
  heartbeat/store/read/finish functions. Migration
  `0028_production_policy_deployment.up.sql:339` grants those entry points to
  `zasp_policy_deployment_worker`; lines 341-379 carry security/readiness and
  fingerprint dependencies.

Expand an existing bounded family row, or add a family row and correct its count.
Name the policy-deployment runtime/repository/SQL/grant chain, its production
worker configuration and P4 decision. Keep signing, scoped device binding,
desired-generation/sequence fencing, temporary-control expiry, verified readback
and gateway acknowledgement semantics explicit. P9 must not remove this worker
or its privileges until the replacement works, or P4 records why this engine
must remain. No runtime fix is requested by this review.

## What passed

I reviewed the binding design/plan, the four-path patch structure, all 36
inventory rows, the report and ledger amendment, and the 728-ID packet/title
listing. Detailed requirement/evidence spot checks covered M2 grants and PATs,
M3 connector and sensor/queue separation, M5 test/Attack Lab jobs, M6 rollout,
M7 exports, M7A-23, M7A-49 and M8 recovery.

The report records successful exact ID/Deliverable/Verify/evidence/owner/class
comparisons and the existing 728-row validator. I did not rerun those checks or
unrelated application suites. Its unchanged 526/141/61 totals are expressly
historical; they do not claim deployed Temporal/OpenFGA acceptance.

M2-05b and M2-33 retain grant scope and desired/applied revision work. M2-38
keeps PAT intersection and immediate SQL revocation. M3-52d keeps SQS/S3/index
acceptance outside the Temporal replacement, while M3 connector sync maps to
P4. M5-32 still contains its original SQS test-job requirement. M7A-23 keeps
run-scoped export evidence and delivery gates; M7A-49 correctly preserves the
original budget requirement, including step/time/token/cost and Organization
concurrency bounds. Recovery and live-provider gates remain open.

The SQL dependency spot check matched scheduler64's worker63 readiness,
release61 orchestration-state call, registration lock and restricted facade
grant. The CLI really stops at `up-to-60`, and production still constructs
`newSecurityAgentProcessor`. The packet records both gaps. It doesn't confuse
Runner tests with a shipped migration route.

The status patch is an append-only hunk. It preserves the interrupted
scheduler64 review, carries the AB/BA invariant and missing-Keys composition
failure forward, and forbids early deletion. The report's byte-prefix and
baseline-digest assertions were already checked by the executor; this review
does not supply independent historical byte proof.

Fix the policy-deployment inventory entry, then re-review that entry and the
affected count/report text only.

## Scoped correction, accepted

I reviewed `/tmp/zasp-temporal-openfga-p0-review.z3VtsN/p0-policy-deployment-fix.patch`.
The added family row closes the P2 finding. It names the production processor,
repository, SQL facades, worker grants, readiness/fingerprint chain, migration
registration and deployed worker configuration. Its P4 decision is explicit;
P9 retirement waits for equivalent evidence, no dual ownership and no remaining
deployment work. Signing, scope/generation/sequence fences, expiry and verified
readback stay. Storage completion cannot stand in for gateway acknowledgement.

The two report count edits correctly state 37 rows; the inventory has 38 lines
including its header. I spot-checked the new CLI and deployment claims against
`agentsec-migrate/main.go:392`, `policy_deployment_repository.go:49`,
`deploy/staging/product/values.yaml:68` and
`deploy/staging/product/templates/workloads.yaml:333`.

No runtime tests or repeated ID/status checks were needed for this correction.
No unresolved findings remain in this P0 review. P1-P10 acceptance remains open.
