# Agent export worker integration plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Execute the single feature batch with focused TDD and one independent spec/quality review.

**Goal:** Connect registered agent-origin jobs to the accepted run-evidence renderer and existing durable export worker without weakening browser exports or prepared-byte replay.

**Architecture:** Extend the worker's closed claim union with an immutable agent binding. Select snapshot schema and renderer revision from that checked origin, then reuse the existing preparation, immutable storage, reconciliation and cleanup lifecycle.

**Tech Stack:** Go1.25.6, existing QueryJSON authority and artifactstore, cached native race tests and owned network-none PostgreSQL fixture.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md. Consumes the accepted renderer and the database contracts in docs/internal/2026-09-19-security-agent-export-database-plan.md.

## Global constraints

- All728 tasks remain in scope. This batch is worker-component integration, not public planner/browser or live production proof.
- Root may implement non-overlapping worker Go changes against the agreed closed contracts while the database batch runs. Registered acceptance and runtime enablement require database acceptance and its frozen interface report; resolve any report/plan difference before those gates.
- Preserve accepted renderer files and release56/57 SQL/pins. Do not edit the database implementer's active files.
- Browser claims retain their exact existing wire shape. Agent claims add only job_origin=agent_run and binding={run_id,step_id,selection} from the immutable database link.
- Unknown origins, malformed/missing bindings and cross-origin revisions fail closed. Never infer expected binding from captured records.
- No new queue, storage driver, provider call or dependency. Keep existing limits, heartbeat join, cancellation, unknown-write accounting and exact-version cleanup.
- No staging, commit, push, external endpoint, secret retrieval, install, image pull or host PostgreSQL. Save before bytes and a task-only patch for inherited files.
- Focused RED/GREEN during implementation; one combined native race batch and one registered worker batch at the end. Do not rerun unchanged renderer acceptance independently.

### Task 1: Origin-aware worker lifecycle

**Files:**
- Modify: services/platform/agentsec-worker/compliance_export_database.go
- Modify: services/platform/agentsec-worker/compliance_export_runtime.go
- Modify only if needed for immutable binding copy: services/platform/agentsec-worker/compliance_export_replay.go
- Create: services/platform/agentsec-worker/security_agent_export_worker.go
- Create: services/platform/agentsec-worker/security_agent_export_worker_test.go
- Create: services/platform/agentsec-worker/security_agent_export_worker_postgres_test.go
- Evidence: docs/internal/security-agent-export-20260919/worker/

**Interfaces:** Existing `complianceExportLease` gains `JobOrigin string` and
`AgentBinding *securityAgentExportBinding`. Empty internal JobOrigin means the
existing browser claim (there is no browser origin field on its wire). The only
other accepted value is agent_run, which requires a validated nonnil binding.
Browser leases must have nil AgentBinding. The existing renderer binding type
has RunID, StepID and Selection; selection fields are Kind, ID, Version and
AssociationDigest. Decode explicit wire keys, not default Go field names.

Add these helpers in security_agent_export_worker.go:

```go
func complianceLeaseRendererRevision(l complianceExportLease) (string, error)
func renderExportPackageByOrigin(ctx context.Context, l complianceExportLease, raw json.RawMessage) (compliancePreparedArtifact, error)
```

The first returns compliance-envelope-v1 for a valid browser lease or
security-agent-evidence-envelope-v1 for a valid agent lease. Invalid unions
return errWorkerExecution. The second switches on that validated result and
calls either renderComplianceExportPackage or
renderSecurityAgentEvidenceExportPackage(ctx,l,*l.AgentBinding,raw).

- [ ] Save before bytes/hashes of touched existing files and read the database report's actual claim/capture/preparation envelopes. Check registered58 readiness and role behavior are supplied by the accepted database batch, not assumed from these Go tests.
- [ ] Add behavioral RED tests using existing complianceDatabaseFixture and complianceRuntimeLease. Build an agent claim from a valid browser claim plus the two declared fields and assert Claim accepts it and preserves independent binding. Current code must fail because its closed decoder rejects these additions. Rejected tests cover absent binding, binding without origin, unknown origin, wrong run/step ID, unknown/duplicate selection keys, duplicate kind/ID, empty/101 selections, noncanonical identities and invalid version/digest.
- [ ] Exercise the actual replay bridge with existing complianceReplayDatabase and complianceReplayDriver. Use securityAgentExportSnapshotFixture for checked raw content, then build captured response with SHA256 of those exact raw bytes. Assert independent binding mismatch fails before Prepare or Put. Explicitly inspect the recorded SQL calls and Put count; an error alone is insufficient.

Example core assertion for the accepted binding case (setup uses the helpers
above and the existing test fixture):

```go
lease := complianceRuntimeLease(t)
snapshot, binding := securityAgentExportSnapshotFixture(t, lease)
lease.JobOrigin = "agent_run"
lease.AgentBinding = &binding
artifact, err := renderExportPackageByOrigin(context.Background(), lease, snapshot)
if err != nil || artifact.RendererRevision != "security-agent-evidence-envelope-v1" {
    t.Fatalf("agent renderer routing: revision=%q err=%v", artifact.RendererRevision, err)
}
```

- [ ] Implement the closed claim union. Preserve all existing scope, generation, attempt, lane, expiry and immutable artifact checks. Decode binding with exact fields and validate every selection using the accepted renderer's canonical-kind rules. Copy the selection slice at lease ownership boundaries so external mutation cannot change rendering authority while heartbeat runs.
- [ ] Capture retains the exact snapshot/sha256/mapping_revision envelope. Select product-evidence-v1/controls for browser leases and security-agent-run-evidence-v1/records for agent leases. Keep full-scope checks and SHA256 over original RawMessage bytes, without reserialization. For agent snapshots validate run/step/ordered selection against the independently claimed binding before accepting content; the renderer still performs its own complete validation.
- [ ] Prepare and LoadPrepared use complianceLeaseRendererRevision, rejecting a revision from the other origin. Keep exact bytes/hash/size/reference/format checks. Do not rerender prepared packages, including after worker restart. No revision fallback or arbitrary JSON-object acceptance.
- [ ] Replace the runtime's hardwired renderComplianceExportPackage callback with renderExportPackageByOrigin. Keep executeComplianceExportPackage's sequencing: Capture, render, persisted Prepare, Put, exact receipt, Finish. Reconcile never calls Put and cleanup never recollects evidence.
- [ ] Cover prepared replay with a renderer that would fail if called, unchanged package bytes, wrong-origin revision, malformed stored checksum, provider error/panic, invalid provider receipt and lost Finish response. Check uncertainty remains recorded and no quota-release path is introduced. Heartbeat must preserve immutable binding and joined cancellation must terminate child work.
- [ ] Add registered PostgreSQL worker acceptance using the database batch's real58 Runner and registered export worker login. Run claim/capture/prepare/finish through the Go authority, not owner operations. Owner-seeded parent/plan prerequisites must be labeled component fixtures. Verify JSON/CSV/readable package bytes from the actual accepted renderer, restart LoadPrepared, permission revocation before publication, cancelled parent, foreign scope and an unchanged browser-origin export in the same batch.
- [ ] Run focused tests first, then one native combined race invocation from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker -run '^(TestSecurityAgentExportWorker|TestComplianceReplay|TestComplianceWorker|TestComplianceRuntime)' -count=1 -v
```

Run the registered tests as a separate CGO-disabled linux/arm64 test binary in
the owned cached PostgreSQL image using the database plan's network-none,
read-only, tmpfs and no-pull command, with agentsec-worker package and
`^TestSecurityAgentExportWorker.*Postgres$`. Retain actual commands and exits;
that execution is not a Go race-detector run. No skipped test counts as evidence.

- [ ] Freeze task-only diff and source hashes, record commands/output/exit status and limitations, self-review, then obtain one independent spec/quality review. Re-review only affected fixes. Update component evidence without enabling the action catalog.

## Remaining connected acceptance

This task does not implement definition activation, planner selection,
registered dispatch routing, settlement-loop scheduling, public export status,
native download grants, UI or release deployment wiring. Those remain required
before M7A-23 can pass connected local acceptance. The database's new link-owned
settlement claim must be integrated explicitly, not through generic parent
reclaim or a needs_human-as-budget fallback. Hosted exact-source CI, approved
advisory/provider checks and deployed canary remain external gates.

## Self-review

Claim binding, capture schema, renderer selection and prepared replay form one
reviewable worker batch. Existing helpers/types named above were inspected in
the current worktree. The new helper signatures are declared here. The accepted
renderer files remain frozen. Database acceptance is a real dependency; this
plan does not permit coding against an unverified placeholder fingerprint.
