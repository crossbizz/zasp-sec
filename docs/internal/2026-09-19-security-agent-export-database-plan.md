# Run-evidence export database authority implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Execute this database feature batch after the renderer contract is frozen. Public workflow and production acceptance remain required follow-on work.

**Goal:** Connect a real run-bound action step to the existing durable export service under registered PostgreSQL authority, preserving browser export behavior and the prior releases.

**Architecture:** Add release58 with an explicit browser/agent_run job origin and one durable action/export link. A private collector proves full-scope run membership and freezes selected redacted evidence. Registered worker entrypoints reuse the existing quota/lease/preparation/receipt/reconciliation/cleanup lifecycle; browser jobs keep their existing session authorization.

**Tech Stack:** PostgreSQL, pgx, Go migrations, existing owned network-none PostgreSQL fixture.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md and docs/internal/2026-09-19-security-agent-export-source-audit.md. Renderer wire contract: docs/internal/2026-09-19-security-agent-export-render-plan.md.

## Global Constraints

- Preserve all728 original tasks. M7A-23 remains component-only. Local fixtures are not provider or production proof.
- Preserve SQL1..57, compiled checksums/pins and default release49 behavior. Release58 is explicit opt-in, with exact unused rollback to57.
- No fabricated session digest or caller-chosen principal, storage path, source bytes or source relationship.
- Selections are nonempty, unique and bounded to100 references.
- Export completion means the immutable package is available, not that a finding is safe/remediated.
- Reconciliation and cleanup may record storage facts and drain existing objects after revocation, but never recollect evidence, upload new bytes or restore publication authority.
- No commit, stage, push, external provider/advisory call, secret retrieval, install or uncached image pull. Preserve inherited changes with before blobs and a task-only diff.
- Owned PostgreSQL image: postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba, --pull=never --network none. No host PostgreSQL.
- Focused RED/GREEN during changes, then one combined registered PostgreSQL/race batch and one independent review. Do not rerun browser/UI suites for each SQL helper.

## State and interfaces

The existing zasp_compliance_export_jobs table remains the only durable export
job queue and storage accounting source. Add job_origin with values browser
(default) and agent_run. Browser requires a32-byte nonzero session_digest and
product-evidence-v1; agent_run requires NULL session_digest and
security-agent-run-evidence-v1. Enforce the complete exclusive union, not just
nullable session_digest. Include job_origin in the scoped principal/idempotency
unique key. Browser create replay/get/grant must filter browser origin.

Add nullable agent_run_id and agent_step_id to jobs. Browser requires both NULL;
agent_run requires both canonical and nonnull. A deferred full-scope foreign key
from these fields to the link's run/step prevents an orphan agent job at commit.
The link references the unique full-scope job/export_id/job_origin tuple and
checks its own job_origin='agent_run', so it cannot attach to a browser job.
Insert both sides transactionally; no blanket application table grants.

Add public.zasp_sa_export_links, owner zasp_discovery_authority, forced RLS and
no application table grants. Full-scope run/step primary key; unique full-scope
export_id referencing the shared job. Persist plan_hash, input_digest,
definition_id/version/digest, authority_principal_id, optional requester_id,
ordered selected references, and settlement receipt. All identity/hash fields
use existing canonical product/digest constraints. Selection entries have the
renderer binding fields source_kind/source_id/source_version/association_digest.
Never update the selection, input or authority binding on replay.

Private source and authorization helpers (not granted to application roles):

```sql
zasp_sa_export_authorize(o text,w text,e text,r text,s text,phase text)
  RETURNS void;
zasp_sa_export_collect(o text,w text,e text,r text,s text,selection jsonb,stamp timestamptz)
  RETURNS jsonb;
```

authorize phase is exactly admit, capture, prepare, publish or retrieve. Unknown
phases fail. Execution phases require the bound active definition/controls and
nonstopped parent; retrieve authorizes the current retrieving browser principal
in the API wrapper and validates persisted binding integrity, without requiring
the completed parent's old execution lease. Format snapshot_at as canonical UTC
RFC3339Nano-compatible text ending Z, matching the frozen renderer contract.

Registered dispatch wrapper, granted only to zasp_security_agent_worker:

```sql
zasp_sa_export_execute_run(o text,w text,e text,r text,worker_value text,
  lease_value text,audit_value text,correlation_value text,
  expected_checksum text,expected_fingerprint text) RETURNS jsonb;
```

It reads the single persisted create_evidence_export step from the parent plan,
not a request-provided step or selection. The persisted step is a closed flattened
object with exactly index, step_id, action, target_id, evidence_ids and
authorization. index is0, action is create_evidence_export, target_id is the
parent run ID, and evidence_ids is the ordered array of objects with exactly
source_kind, source_id, source_version and association_digest. There is no nested
arguments object in persisted storage. authorization is autonomous for autonomous
activation or approval_required for supervised activation; authorized is a step
state, not an authorization result. Supervised execution requires a current
plan-bound approval. Autonomous export has no additional approval floor.
The parent plan has the predecessor's exact definition_id, definition_version,
catalog_version, evidence_ids (original trigger IDs), steps, verification and
expires_at keys. verification is exactly {"kind":"export"}; trigger_digest is
bound in the plan row. Compute plan_hash from canonical PostgreSQL plan JSON and
input_digest from its exact flattened step, following the existing planner.
The later planner adapter constructs the step from checked context. This
batch's registered tests may seed the prerequisite plan as an explicitly labeled
component fixture; only the later public browser flow proves planner admission.

The dispatch result is a closed object with organization_id, workspace_id,
environment_id, run_id, run_version, step_id, export_id, state (pending), replayed.
run_version is the actual persisted parent version, not a fabricated counter. The same
step/input always returns the original export, including after worker restart.
An altered plan/input/selection must fail without a second reservation/job.

Migration Go interface:

```go
func ProductionSecurityAgentExports() Metadata
func SecurityAgentExportsFingerprint() string
func (runner *Runner) UpProductionSecurityAgentExports(ctx context.Context) error
func (runner *Runner) DownProductionSecurityAgentExports(ctx context.Context) error
```

Expose `zasp_sa_export_readiness(text,text) RETURNS boolean` to the registered
API/agent/export-worker roles using their existing readiness conventions.
No new broad authority role or login is needed. Shared export worker registration
must continue to verify exact role membership and reject mixed authority.

Registered API wrappers, granted only to zasp_security_agent_api:

```sql
zasp_sa_export_get(o text,w text,e text,r text,s text,principal_value text,
  session_value bytea,csrf_value text,expected_checksum text,
  expected_fingerprint text) RETURNS jsonb;
zasp_sa_export_grant(o text,w text,e text,r text,s text,principal_value text,
  session_value bytea,csrf_value text,token_value text,format_value text,
  operation_value text,expected_checksum text,expected_fingerprint text)
  RETURNS jsonb;
```

Both resolve the export solely through the full-scope run/step link. get returns
exactly export_id, state, phase, failure_code, created_at, retrieval_expires_at,
mapping_revision, snapshot_at, cleanup_state, selection and artifact. The
nullable artifact contains only sha256 and size; no storage reference or source
bytes. cleanup_state is retained, pending or deleted, derived from the existing
storage state. Other enum/time/null values retain the shared export job meaning.
selection is the exact persisted ordered binding array, not a fresh scan.

Grant operations and formats retain issue/read/consume/integrity_failure and
json/csv/readable. Non-read results are exactly expires_at and consumed. The
private read result contains reference, version, size, sha256,
renderer_revision, read_expires_at and binding. binding is exactly run_id,
step_id and selection. The API must not expose the read result directly.

Registered parent settlement, granted only to zasp_security_agent_worker:

```sql
zasp_sa_export_settlement_claim(worker_value text,lease_value text,
  lease_seconds integer,claim_limit integer,expected_checksum text,
  expected_fingerprint text) RETURNS jsonb;
zasp_sa_export_settle(o text,w text,e text,r text,worker_value text,
  lease_value text,audit_value text,correlation_value text,
  expected_checksum text,expected_fingerprint text) RETURNS jsonb;
```

Settlement claim returns an array of closed organization_id, workspace_id,
environment_id, run_id, step_id, export_id, run_version, lease_expires_at objects.
Validate the existing worker/token conventions, lease_seconds30..300 and
claim_limit1..25. Lease ownership, token digest and expiry belong to the export
link, not the parent. Select only unsettled links whose child is terminal or
parent is stopped; skip locked rows/live leases and use bounded fair ordering.
Do not spend execution attempts, reserve planner budget, re-plan, or grant upload
authority. A pending child with an active parent is not settlement-claim eligible.
Expired budgets and revoked actors cannot strand recording existing child facts.
The generic parent budget-claim implementation stays unchanged.

It reads the linked job's durable receipt; no caller-supplied success, proof or
artifact fields. Return a closed run_id, run_version, step_id, export_id, state, reason,
settled, replayed object. Pending uses state=verifying, reason=export_pending,
settled=false. Completed uses needs_human/export_available; failed uses
needs_human/export_failed. A cancelled parent remains cancelled with
export_cancelled. Every terminal result has settled=true, and stable replay
cannot mutate the previous receipt. Pending may preserve the parent version;
terminal settlement advances it only when the parent actually transitions, and
replay returns the persisted receipt version. An already-stopped parent retains
its state, last_error_code and version. Non-cancelled stopped parents use receipt
reason export_parent_stopped; cancelled parents use export_cancelled. Persist
existing child/package facts without resurrecting the parent or admitting work.
Cleanup is projected from the job and can
finish after the parent is stopped without a new parent execution lease.
Settlement validates the current link settlement lease. Exact committed receipt
replay accepts only the original bound request identity, including after lease
expiry; an unrelated stale worker cannot acquire new authority by replay.
Dispatch requires the current parent lease; later export-worker capture/prepare/
finish use the export lease and persisted parent binding, not an expired agent
lease from initial dispatch. This avoids giving a worker two conflicting leases.

Shared export claim preserves the exact browser envelope. Agent-origin claims
add job_origin=agent_run and binding={run_id,step_id,selection}, read from the
immutable link independently of snapshot content. Capture retains the outer
snapshot/sha256/mapping_revision envelope with the agent-specific revision and
closed snapshot. Preparation and replay check renderer revision against origin.

### Task 1: Durable registered export authority

**Files:**
- Create: services/platform/migrations/security_agent_exports_release.go
- Create: services/platform/migrations/production_security_agent_exports.go
- Create: services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
- Create: services/platform/migrations/sql/0058_production_security_agent_exports.down.sql
- Create: services/platform/migrations/sql/fragments/security_agent_export_sources.sql
- Create: services/platform/migrations/sql/fragments/security_agent_export_jobs.sql
- Create: services/platform/migrations/sql/fragments/security_agent_export_links.sql
- Create: services/platform/apiserver/security_agent_export_postgres_test.go
- Create: services/platform/apiserver/security_agent_export_release_postgres_test.go
- Modify narrowly if required for explicit58 recognition: services/platform/migrations/production_audit_exports.go
- Modify narrowly: services/platform/migrations/production_compliance.go RegisterComplianceWorkers explicit58 guard/comment; preserve exact56 historical Up/Down readers and role verification. Save before bytes and prove actual Runner registration on58.
- Do not edit accepted compliance_jobs.sql or57 fragments. Save/clone and evolve functions from the new release.
- Evidence: docs/internal/security-agent-export-20260919/database/

- [ ] Save before hashes/bytes for every existing touched file and establish fixture setup using runVersionedExistingTestFixture and precisionMigrationRunner. Upgrade accepted56 then57 using their actual Runner methods. New58 must be applied through its Runner after initial fingerprint calibration.
- [ ] Write registered failing tests before authority implementation. Test full organization/workspace/environment/run/step membership, same finding legitimately attached to two different runs, unrelated same-tenant finding, stale version, forged run-prefix, duplicate/empty/101 selections, changed plan/input and wrong/expired worker lease. Observe actual behavioral refusal failures, not just a missing SQL symbol.

The fixture helper must open a separate connection using the existing registered
worker login, with no SET ROLE or table-owner shortcut for the operation under
test. Use a literal expected source identity. Example assertion pattern:

```go
var result json.RawMessage
err := worker.QueryRow(ctx,
  `SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
  o, w, e, run, workerID, leaseToken, auditID, correlationID,
  migrations.ProductionSecurityAgentExports().Checksum(),
  migrations.SecurityAgentExportsFingerprint()).Scan(&result)
if err != nil { t.Fatal(err) }
var got struct { ExportID string `json:"export_id"`; Replayed bool `json:"replayed"` }
if json.Unmarshal(result, &got) != nil || got.ExportID == "" || got.Replayed {
  t.Fatalf("first dispatch did not admit one export: %s", result)
}
```

All variables above come from the owned fixture: scope from its callback,
run/worker/lease from registered claim, audit/correlation from test product IDs.
The test must inspect full scoped job/link/effect/audit counts before and after
each rejected call, not merely assert a nonnil error.

- [ ] Implement source collection using exact receipt/run joins. Finding and
attack_path content must match the run-associated version; if historical
content isn't retained, refuse explicitly. Do not read newest as a substitute.
For findings export the public finding projection (identity, title, source,
rule, severity, status, agent/path references, version and evidence references),
never raw provider credentials. For paths export the public path projection
with ordered nodes/evidence and validated endpoints/state/version. Extra
references in a source record are references only, not recursive permission to
fetch their bodies.
- [ ] Runtime decisions resolve exact receipt session/sequence and verify the
receipt digest containing device/event/request digest. Do not apply newest-event
or five-minute admission freshness. Export only session/event/device identity,
sequence, decision, outcome, policy_version, occurred_at and request digest;
no raw request payload or credential material. Source-read authority is
investigate_sessions plus view.
- [ ] Run audit uses the existing run-context audit metadata allowlist, exact
run join and view_audit plus view. Use source_version1 for an immutable audit
event; association_digest is its persisted event digest. Existing-test and
Attack Lab evidence reuse their checked public step projections with full
link/effect/input validation. Freeze that exact projection and digest, including
pending/failed/cleanup states. Do not resolve private object keys from digests.
- [ ] Manual receipt export is an explicit run-intent record: original64-hex
trigger ID, kind, trigger version, digest and received_at, plus run/definition
identity. It makes no claim to recover an event body. Refuse mismatched receipt
digest/ID. It still needs a nonsimulated persisted run and authorized principal.
- [ ] For every source, emit the renderer's closed record shape. content_json is
the exact redacted JSON text; content_sha256 is SHA256 of those UTF-8 bytes.
association_digest remains distinct. Collect all selected records in one
statement snapshot and reject any missing/overflow entry atomically.
- [ ] Authorize the persisted exact definition-version actor, checking its
definition digest and current full-scope membership/manage_workflows/source
permissions. Manual invocation also checks requester authority. Do not treat
scheduled requested_by as a user ID. Recheck time-dependent authority after
lock waits, including role/scope changes, definition drift and lease expiry.
- [ ] Implement the exclusive origin constraint and shared quota admission.
Add browser-origin filters to create replay/get/grant. Retain existing policy
limits and fair scope claiming. Match action replay against the immutable link
before reserving capacity. Add narrow job-origin dispatch at capture, prepare
and finish; browser calls keep existing authorization unchanged.
- [ ] Capture, prepare and publication must validate agent binding/current
permissions and parent stop. Serialize parent cancellation and new logical
upload admission with a documented common lock order. Do not claim a database
transaction can undo an already-admitted provider call. Once upload intent is
durable, uncertain bytes retain quota and cleanup responsibility. No provider
work is performed inside a database transaction.
- [ ] Preparation accepts only the exact renderer revision appropriate to job
origin, validates package size/digest/reference, and stores immutable bytes.
LoadPrepared reuses those bytes. Finish binds the immutable provider receipt;
reconciliation records storage facts without setting failed/revoked jobs to
completed. Cleanup never requires the original actor to remain authorized.
- [ ] Add registered agent status/grant wrappers only after core source checks
exist. Reads require current browser session/CSRF and every selected source
permission, not view_compliance. Reuse the existing grant table, expiry, read
lease, quota and consume behavior; preserve owner-only browser compliance
semantics. Agent grants bind the actual retrieving principal and source set.
Use the exact signatures/envelopes above and record their implementation in
the report for the following API integration batch.
- [ ] Parent settlement binds export ID/package checksum/version/size and
retention status to the original effect/input. Successful export settles the
step as succeeded and the parent as needs_human with an export-specific reason,
never remediated. Cancellation preserves pending child cleanup and cannot
resurrect a stopped parent. Closed projection must distinguish pending, failed,
expired and cleanup-pending exports.
- [ ] Assemble58 and its exact live fingerprint including new tables,
constraints, role grants and functions. Evolve predecessor readiness via
saved function definitions/owners/ACLs, following57's guarded ancestry pattern.
Do not change56/57 constants. Empty rollback restores exact57 catalog/ACLs;
retained links/jobs/receipts/controls, including disabled controls, block
destructive downgrade.
- [ ] Run one affected registered PostgreSQL batch. Tests include first
dispatch/replay and changed-input refusal, two scopes, after-lock revocation,
historical runtime event with a newer event present, same finding/different
versions, cancellation/dispatch race, capture/restart with frozen bytes,
uncertain upload bookkeeping, read/consume revocation, retained cleanup quota,
cross-origin ID/idempotency/grant confusion, browser compliance regression and
release-cycle/ACL restoration. Use existing owned fixture lifetime/join helpers.
Also prove registered settlement claim/restart with no pending attempt churn,
expired-budget/stopped-parent draining, stale settlement lease rejection and
lost-reply replay. Owner-seeding a lease is not proof of settlement scheduling.

```sh
fixture_dir=$(mktemp -d /private/tmp/zasp-export-db.XXXXXX)
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o "$fixture_dir/apiserver.test"
/usr/local/bin/docker run --rm --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount "type=bind,src=$fixture_dir/apiserver.test,dst=/export.test,readonly" --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport.*Postgres$' -test.v -test.timeout 300s
```

Run from services/platform. The cached image was freshly inspected as
linux/arm64. The tests' existing disposable initdb/postgres helpers operate only
inside this owned container. Give it a unique task-owned name/cid tracking via
the existing ownership helper if additional lifecycle control is needed; never
clean unrelated containers. Join the run and verify exit. Tests must run, not
skip. This CGO-disabled PostgreSQL binary is not a Go race-detector run. Run
native Go -race only for any new non-PostgreSQL migration/interface tests, in
the same feature verification batch, and distinguish the two evidence types.
Preserve commands, environment names without secrets, output and exit status.
Never substitute a source-text contract for a registered operation.

- [ ] Freeze task-only patch/manifest, self-review and report for one independent
spec/quality review. Report every implemented public/private signature and
wire envelope so the next worker/API/UI batch consumes exact contracts.

## Follow-on required before M7A-23 acceptance

The worker/API/UI batch must connect real definition activation, planner
selection and dispatch to this authority, consume the renderer without relaxing
browser decoders, project truthful status, expose native downloads, wire exact58
runtime readiness/deployment and CLI upgrades, and exercise the mounted flow
without seeding plans/links/settlement. Include process restart, lost upload and
settlement replies, source/permission drift, foreign reads, native byte integrity
and cleanup lag. Then full UI/type/lint/build, generated contracts, independent
feature review and external publication gates. This database batch alone does
not satisfy the original task or the728-task goal.

## Plan self-review

One database task owns source collection, origin-aware lifecycle and public
authority wrappers, avoiding separate reviews of inseparable authorization
changes. Renderer code stays untouched. The later runtime consumes the declared
admission/status/grant/settlement envelopes and existing prepared-artifact shape.
All original feature requirements remain either in Task1 or the named connected
workflow/production gates; no local acceptance promotion is authorized here.

Specific cross-boundary risks for implementation/review: lock ordering across
shared jobs and parent cancellation; existing56/57 fingerprint ancestry after
table changes; historical runtime resolution without admission freshness;
membership changes during waits and storage reads; browser-origin replay/query
isolation; post-dispatch export authority without requiring the old agent lease.
