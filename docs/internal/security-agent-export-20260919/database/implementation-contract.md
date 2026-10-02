# The database boundary

This is release58's registered component contract. It does not prove public planner selection, an API/UI workflow, live provider delivery or production readiness. All SQL application calls in the owned tests use registered, separately connected logins without SET ROLE. Owner writes create fixture prerequisites only.

The shared zasp_compliance_export_jobs table is still the sole job/lease/quota/package/grant/cleanup service. zasp_sa_export_links binds an existing parent run and action step to exactly one job. Forced RLS and owner-only tables apply. Browser jobs have nonzero32-byte session digests and product-evidence-v1 mapping. Agent jobs have NULL sessions, full-scope parent/step bindings and security-agent-run-evidence-v1 mapping. Deferred full-scope foreign keys prevent orphan agent jobs; origin participates in idempotency uniqueness.

## Registered entrypoints

All return jsonb. Checksum/fingerprint are the exact release58 pair unless noted. Application callers require read committed, the existing registered role and no mixed zasp_* role membership. Parent dispatch uses the current shared parent worker lease. Settlement has its own link lease and never renews the parent, reserves model/step budget or grants upload authority.

```sql
zasp_sa_export_execute_run(
 o text,w text,e text,r text,worker_value text,lease_value text,
 audit_value text,correlation_value text,expected_checksum text,expected_fingerprint text)

zasp_sa_export_settlement_claim(
 worker_value text,lease_value text,lease_seconds integer,claim_limit integer,
 expected_checksum text,expected_fingerprint text)

zasp_sa_export_settle(
 o text,w text,e text,r text,worker_value text,lease_value text,
 audit_value text,correlation_value text,expected_checksum text,expected_fingerprint text)

zasp_sa_export_get(
 o text,w text,e text,r text,s text,principal_value text,session_value bytea,
 csrf_value text,expected_checksum text,expected_fingerprint text)

zasp_sa_export_grant(
 o text,w text,e text,r text,s text,principal_value text,session_value bytea,
 csrf_value text,token_value text,format_value text,operation_value text,
 expected_checksum text,expected_fingerprint text)

zasp_sa_export_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean
```

execute_run, settlement_claim and settle are granted only to zasp_security_agent_worker. get and grant are granted only to zasp_security_agent_api. Readiness is granted to the existing discovery API, Security Agent API/worker and compliance worker/cleanup roles. There are no new application table grants.

Dispatch returns exactly organization_id, workspace_id, environment_id, run_id, run_version, step_id, export_id, state and replayed. state is pending; the persisted parent becomes verifying with its old execution lease cleared. The immutable dispatch worker/token digest binds a lost-reply replay before any quota or step reservation. Changed inputs and unrelated tokens are refused. run_version is the actual transitioned parent version.

Settlement claim returns an array of exactly organization_id, workspace_id, environment_id, run_id, step_id, export_id, run_version and lease_expires_at. Lease seconds30..300 and claim count1..25. Only unsettled links with terminal children or stopped parents are eligible. It skips live leases and locked rows, with per-scope ordinal ordering. Pending active parents produce no claim and no attempt churn.

Settle returns exactly run_id, run_version, step_id, export_id, state, reason, settled and replayed. Pending is verifying/export_pending/false. A valid completed immutable artifact sets the active parent to needs_human/export_available and the step to succeeded, never remediated. Child failure uses export_failed. Already stopped parents keep their state, last_error_code and version; reason is export_parent_stopped, or export_cancelled for cancelled. Lost-reply replay returns the persisted version and receipt, requiring the original worker/token/audit/correlation identity even after lease expiry. Private settlement facts bind export ID, artifact checksum/version/size, storage state, retained bytes and retrieval expiry into the original effect's result digest.

get returns exactly export_id, state, phase, failure_code, created_at, retrieval_expires_at, mapping_revision, snapshot_at, cleanup_state, selection and artifact. artifact is null or {sha256,size}; cleanup_state is retained, pending or deleted. Retrieval expiry is separate from job state. Object keys and native package bytes are not in this public status projection.

grant reuses the shared grant table, formats json/csv/readable, operations issue/read/consume/integrity_failure, limits, expiry, read lease and single-use rules. issue/consume return {expires_at,consumed}. read is private to the API and returns reference, version, sha256, size, renderer_revision, read_expires_at and binding={run_id,step_id,selection}. The retrieving principal's current full-scope session, CSRF, membership and source permissions are checked before and after blocking work. Agent retrieval does not require view_compliance, manage_workflows or ownership by the original definition actor. Existing browser compliance retrieval remains owner-only and browser-origin-only.

## Existing worker transport

Shared export claim signatures and browser envelopes are unchanged. An agent claim adds only job_origin="agent_run" and binding={run_id,step_id,selection}, loaded from the immutable link independently of snapshot contents. Capture still returns exactly snapshot, sha256 and mapping_revision.

Agent prepare accepts security-agent-evidence-envelope-v1; browser prepare accepts compliance-envelope-v1. New preparation and persisted-byte replay both check origin/revision. The existing exact byte digest, size, reference and format-size validation remains in force. Prepare/finish/claim/capture keep the predecessor56 checksum/fingerprint API, with58 ancestry readiness checked internally. No caller-controlled principal, source body or storage path is accepted.

Cancellation and new storage admission lock parent before job. Dispatch also holds the existing organization admission guard before the parent. Settlement locks parent, link, then job; link claiming takes only link locks. Durable upload intent means an already admitted provider call can still be in flight. Cancellation expires retrieval and marks uncertain work for reconciliation; retained bytes stay charged until exact cleanup. Reconciliation can record storage facts after actor revocation but cannot publish a failed/cancelled job or create new bytes. Cleanup does not require the original actor.

## Sources and exact plan binding

The persisted step is closed: index, step_id, action, target_id, evidence_ids, authorization. index0, action=create_evidence_export, target_id=parent run. authorization is autonomous or approval_required according to the persisted activation. Supervised mode requires a current plan-bound approval; autonomous has no extra approval floor.

The canonical parent plan is closed: definition_id, definition_version, catalog_version, evidence_ids (original trigger ID), steps, verification={kind:export}, expires_at. expires_at is the predecessor planner's UTC microsecond form YYYY-MM-DDTHH:MM:SS.USZ and matches the row expiry. The plan row trigger_digest matches the full-scope run receipt. Exact canonical PostgreSQL JSON text is hashed for plan and flattened step. Admission checks the persisted definition-version digest and actor, current definition/control state, active actor membership and effective direct/group source permissions. It rechecks authority and budget after blocking writes.

Every selected reference has exactly source_kind, source_id, source_version and association_digest. Selection is ordered, nonempty, unique by kind/id and bounded to100; versions are positive safe JSON integers. Public IDs are canonical except manual's original64-hex trigger ID. Association digests have the sha256: prefix. Records add only content_json and content_sha256. The latter is raw SHA256 of the exact UTF-8 redacted JSON text and is not the association digest.

finding and attack_path require exact full-scope run/receipt/live-version agreement and use checked public projections. Missing historical content is refused; newest content is never substituted. Extra evidence IDs remain references, not recursive fetch authority.

runtime_decision resolves the exact receipt session/sequence and digest binding device/event/request digest. It ignores admission freshness and newer events. Its allowlist is session_id, event_id, device_id, sequence, decision, outcome, policy_version, occurred_at and request_digest. It needs view plus investigate_sessions.

run_audit requires exact scope/run/event membership, immutable source_version1 and the persisted event digest. Only id, run_id, scope IDs, actor_reference, event_kind, correlation_id and occurred_at are exported; never the audit body. It needs view plus view_audit.

manual exports the original run-intent receipt: run_id, definition_id, trigger_id, trigger_kind, trigger_version, trigger_digest and received_at. It makes no claim to recover an event body. Receipt ID/digest mismatch is refused. A manual receipt always requires a canonical requester with current authority; a worker-shaped requested_by is refused. Only explicit finding/attack_path/runtime_decision receipts use scheduled authority, backed by the exact version-bound definition actor and registered caller. Canonical requesters on those receipts are also checked.

existing_test and attack_lab source_id is the original linked action step ID in the same parent run, source_version is that step's persisted version, and association_digest is sha256:effect.result_digest. A missing digest is refused, including a pending proof without a retained result digest. Full link/action/input/effect checks precede the existing checked public_step projection. Private object keys are never recovered. Pending and cleanup states stay truthful. The current one-step public planner cannot produce all multi-step prerequisites; these tests seed retained component prerequisites and do not claim public workflow acceptance.

Collection uses one STABLE statement snapshot for all selected sources. It refuses missing records atomically, limits each content string to65536bytes and the complete snapshot to4194304bytes, then freezes the shared job snapshot. Replay uses frozen bytes after source drift.

## Private helpers and release plumbing

No application EXECUTE grants exist on these helpers:

```sql
zasp_sa_export_selection(selection jsonb) RETURNS void
zasp_sa_export_collect(o text,w text,e text,r text,s text,selection jsonb,stamp timestamptz) RETURNS jsonb
zasp_sa_export_principal_ready(expected_role text) RETURNS boolean
zasp_sa_export_principal(o text,w text,e text,actor text) RETURNS void
zasp_sa_export_authorize(o text,w text,e text,r text,s text,phase text) RETURNS void
zasp_sa_export_source_permissions(o text,w text,e text,actor text,selection jsonb) RETURNS void
zasp_sa_export_job_authorize(j zasp_compliance_export_jobs,phase text) RETURNS void
zasp_sa_export_capture_job(j zasp_compliance_export_jobs) RETURNS jsonb
zasp_sa_export_api_require(expected_checksum text,expected_fingerprint text) RETURNS void
zasp_sa_export_browser(o text,w text,e text,actor text,session_value bytea,csrf_value text,id_value text) RETURNS void
zasp_sa_export_cancel_child(o text,w text,e text,r text) RETURNS void
zasp_sa_export_function_identity(value oid) RETURNS text
zasp_sa_export_live_fingerprint() RETURNS text
zasp_sa_export_guard() RETURNS boolean
zasp_sa_export_prior.predecessor_ready(text,text) RETURNS boolean
zasp_sa_export_prior.grant_core(text,text,text,text,bytea,text,text,text,text,text,text,text) RETURNS jsonb
```

authorize phases are exactly admit/capture/prepare/publish/retrieve. Unknown phases fail. Retrieve checks immutable integrity; API wrappers check the current retrieving principal. Migration-only zasp_sa_export_save(text) is removed before installation ends.

Runner.UpProductionSecurityAgentExports and DownProductionSecurityAgentExports use exact predecessor/current registry and readiness checks. Only explicit58 cases were added to the inherited audit configuration reader and RegisterComplianceWorkers guard. Historical56/57 Up/Down readers and constants are unchanged. Saved pg_get_functiondef, owners and ACLs restore unused rollback exactly. The additive compliance catalog uses logical live-column ordinals so dropped58 columns do not invalidate restored57 on re-upgrade; names/types/defaults/constraints/roles remain fingerprinted. New table/function/ACL/constraint/index/policy/trigger identity participates in58's live fingerprint. Retained links, agent jobs, definitions/history, plans, steps, effects and export controls (including disabled controls and control receipts) refuse destructive downgrade.
