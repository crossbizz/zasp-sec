# Run-scoped evidence export source audit

Original M7A-23 requires create_evidence_export to use the existing export
service and reference only run-scoped evidence IDs. This is read-only source
evidence, not an implemented action or runtime acceptance. M7A-22's three local
implementation batches are accepted; production acceptance remains external.

## Existing boundaries

`services/platform/securityagent/builtin_actions.go` labels the export action
low risk with no mandatory approval floor. Its component validator compares
run_id to the action run and accepts up to100 comma-separated strings beginning
with runID plus a colon. That prefix does not prove persisted tenant/run
membership. Production authority must resolve the actual evidence association.

`services/platform/apiserver/compliance_exports_repository.go` accepts only
framework/control selection. Create requires fresh browser authentication and
its database calls use a session digest plus view, view_audit and view_compliance.
This is not an agent-worker entrypoint. Do not impersonate a browser to reuse it.

`services/platform/migrations/sql/fragments/compliance_jobs.sql` fixes mapping
revision to product-evidence-v1 and captures configured control/source families.
The table checks this revision; preparation checks compliance envelope revisions.
`agentsec-worker/compliance_export_render.go` accepts closed controls snapshots
and recognized SOC2/HIPAA mappings. Converting arbitrary run evidence into that
shape would invent control mappings and change the requested contract.

`services/platform/audit/export.go` explicitly describes ExportBinding as a
destination, not a source filter. Its organization-wide export may contain other
workspace/environment scopes. A run label cannot make that package run-scoped.

Reusable export mechanisms do exist: frozen prepared bytes, immutable provider
version receipts, bounded upload reconciliation, read-lease-aware exact-version
cleanup, retained quota during uncertainty and single-use browser grants.
Reusing them does not make the current source collector or authorization right
for an agent-run export.

## Proof projection is not raw artifact authority

`security_agent_existing_test_public.sql` exposes reference digests, version,
checksum and size, not raw private object references. It validates link/effect/
step identity and immutable settlement snapshots. Preserve that redacted
contract unless a separately authorized source read permits additional content.
Do not derive storage keys from proof digests or export private input/output
artifacts by default.

Current activity reads use source-specific permissions: view for runs,
investigate_sessions for session material and view_audit for audit material.
Requiring view_compliance merely because storage originated there would not
authorize the selected source evidence. Capture and download must check the
actual source kinds, including permission changes after waits.

## Authorization lasts beyond admission

Root inspected compliance_jobs.sql lines29-34 and195-254 on2026-09-19.
Jobs require a principal and a32-byte browser session digest. Capture calls
compliance_authorize both before and after freezing the source snapshot.
Artifact preparation and completion repeat that authorization in the execute
lane. An agent-only admission adapter cannot safely reuse this lifecycle by
inventing a session digest or removing the browser checks.

The next design must define an explicit job origin and authorization mode,
with current source authority checks for agent jobs at capture, preparation,
publication and retrieval. Preserve existing browser-job semantics. Separate
reconciliation already records uncertain storage facts after requester
revocation without publishing a completed export; retain that distinction so
revocation cannot strand cleanup or turn reconciliation into authorization.
These are source-derived constraints, not evidence of an implemented adapter.

## Direction for the next design

### Run membership is a relation, not an ID prefix

The persisted execution schema in0018_security_agent_execution.up.sql has a
full organization/workspace/environment/run key. Its trigger receipt binds
that run to trigger kind, ID, version and digest. Plans have the same full run
key plus a plan hash. Security Agent audit rows carry scope and run_id, with
optional step_id. These are candidate trusted joins for export membership.

In contrast, existing_test_planner.sql returns ordinary product IDs in its
untrusted_evidence and plan evidence_ids. The component-only builtin validator
expects runID-colon-prefixed strings. Neither this prefix nor a bare product ID
proves membership. The production connection must resolve a closed typed
reference against the persisted full-scope run association and freeze its
source version/digest. Do not retrofit invented prefixes onto public source IDs.

The same finding can legitimately trigger two runs. Authorization must prove
membership in the selected run, not global exclusivity of the finding ID.
Include a regression with shared finding IDs and differing trigger versions,
as well as a different unassociated finding in the same tenant. A matching
current finding alone must not replace the version attached to the run. If the
historical content cannot be recovered or checked against retained evidence,
fail the requested selection explicitly; do not silently export its new value.

Existing-test proof has its own stronger membership check: its public_step
projection joins link, effect and step, then validates settlement snapshot,
receipt and proof digest. Reuse that checked redacted projection when selecting
such evidence, not a raw read of private artifact references. Pending proof
must be described as pending, never serialized as successful verification.

The next design must name each supported source kind and its authority check.
Selected records must be nonempty, unique and bounded; reject any unresolved
member atomically. No implicit expansion from one finding into all tenant
evidence, and no new evidence discovered during retry. The export's manifest
must retain the selected run, typed source identity, source version/digest and
snapshot time so its scope is independently inspectable.

Preferred: add a closed run-evidence job kind and renderer to the existing
durable export mechanism, with a separate lease-bound agent admission wrapper,
trusted run-evidence collector and source-specific download authorization.
Freeze the exact authorized set and bytes; never widen it during retry. Keep
current compliance jobs/decoders working unchanged. Use an additive release
after57; this audit does not allocate the next schema number.

A direct compliance endpoint call exports the wrong set and requires browser
authority. A second independent upload/grant/cleanup service duplicates accepted
safety mechanisms and does not meet the requirement to use the existing service.

The design still must define membership, snapshot boundary, empty/missing/expired
evidence behavior, source permission rechecks, job-kind capability fencing,
plan binding, durable action/export linkage, output schema and result semantics.
No blanket export-all or fabricated compliance control is selected. Export
completion must not claim the underlying security condition was remediated.

Connected acceptance must cover two same-tenant runs with different evidence,
foreign tenants, forged prefixes, revocation during waits, restart/lost upload
reply, immutable native download bytes and cleanup lag. Local provider fixtures
remain local proof. M7A-23 stays component-only until the real connected path
and production acceptance gates are verified.

## Collector constraints confirmed after Task3 acceptance

The existing trigger helper is an admission reader, not an export collector.
`security_agent_existing_test_admission.sql` function
`zasp_production_security_agent_existing_tests_trigger` checks finding identity
with a digest of kind/ID/version, and attack-path identity with kind/ID/version/
state. These are not hashes of complete source content. The export manifest
must distinguish the retained association digest from the digest of the frozen
export record; never label the former a full-content integrity proof.

Its runtime-decision branch deliberately selects the newest event in a
five-minute window and the newest unrevoked credential. Reusing this helper
unchanged for export would reject retained evidence after five minutes or select
a different event. The collector must instead resolve the receipt's exact
session/sequence and verify the retained digest (which includes device, event ID
and request digest). Current source-read permission remains mandatory. A newer
event must never replace the receipt-bound event. Test collection after the
admission freshness window, with another newer event present.

Candidate source inventory, based on current persisted readers:

| Kind | Trusted association and source | Export boundary |
| --- | --- | --- |
| finding | Full-scope trigger receipt plus `zasp_risk_findings` exact version | Explicit refusal if retained content cannot be recovered; association digest and exported content digest are separate. |
| attack_path | Receipt plus `zasp_risk_attack_paths` exact version | Preserve checked path validity and version, never substitute current path. |
| runtime_decision | Receipt plus `zasp_runtime_gateway_events` session/sequence and matching receipt digest | Exact historical event, source-specific investigation permission, no newest-event admission query. |
| run audit | `zasp_security_agent_audit` joined to the selected full-scope nonsimulated run | Reuse the explicit metadata allowlist in `zasp_production_security_agent_run_context_audit`; no private audit body. |
| existing-test proof | Full-scope run/step link, effect and input digest | Reuse `zasp_production_security_agent_existing_tests_public_step` validation and redaction; no private artifact fetch. |
| Attack Lab proof | Full-scope run/step link and checked effect | Reuse `zasp_sa_attack_lab_public_step` in `security_agent_attack_lab_links.sql`; retain pending/cleanup states. |

The trigger table also permits `manual`. That enum alone does not establish
retained source content. Resolve its actual admission semantics before defining
manual evidence serialization. Do not silently drop this kind or invent bytes.
Likewise `requested_by` is bounded text, not itself proof of current human
membership: scheduled run ownership needs a checked persisted principal binding
before agent-origin export authority can be implemented.

This inventory constrains the implementation plan. It is not a claim that the
collector, worker, download flow or M7A-23 is implemented.

### Resolved ownership and legacy identity

The existing-test scheduler calls admit with worker_value as actor_value;
admit saves it in requested_by. That field cannot authorize source reads for
an automatic export. Exact definition-version history retains actor_id and
definition_digest.0018 activation inserts the actor explicitly, and the55
mutation provenance fragment replaces the mirror's session_user with the
checked product principal for that newly created version only. The design now
uses this exact version-bound actor, current membership and current full-scope
permissions; a newer actor is not a fallback. Manual invocation also requires
the requesting principal's authority. Database enforcement is still pending.

Legacy0018 create_run permits manual triggers and stores trigger_id as hex of
trigger_digest. No source content accompanies that receipt. Manual export can
describe the checked run/trigger intent, but cannot claim to reconstruct an
underlying event from a hash. Preserve that64-hex identity; do not fabricate a
product ID. The renderer contract records this closed kind-specific exception.

### Shared export lifecycle integration points

Fresh inspection confirms `compliance_jobs.sql` currently hardcodes browser
authority in capture (before and after collection), preparation and finish.
Jobs require a nonnull32-byte session digest and product-evidence-v1 mapping.
The Go capture decoder requires controls, and Prepare rejects every renderer
revision except compliance-envelope-v1. The new renderer alone changes none
of these gates. A proper agent-origin connection must update both SQL and Go
closed unions, not only select a new render function.

The existing catalog fingerprints export table columns, constraints, policies,
indexes and roles. Adding an origin or relaxing the session nullability changes
that catalog. The additive release must evolve the checked capability chain
and preserve exact predecessor rollback, not overwrite the accepted56 pin or
pretend the old fingerprint still describes the changed table. Registered
browser-origin regression and downgrade tests must cover that transition.

The render batch now has an implementation plan and an active implementer.
Root owns the connected admission/collector/runtime plan; no source capture,
export admission, native download or UI acceptance has yet been claimed.

### Worker handoff findings, 2026-09-19

The accepted renderer is now locally reviewed. Inspection of the real worker
shows four integration requirements that its isolated tests cannot establish:

1. `compliance_export_database.go` claim has no origin or run-selection binding.
   Capture returns only snapshot, sha256 and mapping_revision. Agent claims need
   a checked immutable binding from the link, independent of captured content;
   deriving expected selection from that same snapshot would make the renderer's
   binding check circular. Preserve the browser claim's existing closed shape.
2. Both Prepare and LoadPrepared reject revisions other than
   compliance-envelope-v1. Add an explicit origin-specific revision check in
   both paths. `compliance_export_runtime.go` must select the matching renderer
   before calling the existing prepared-byte replay bridge. Prepared replay must
   continue to skip capture/render and retain the uncertain-write accounting.
3. `security_agent_runtime.go` interprets any needs_human execution result as
   a budget stop with empty action fields. Export completion needs an explicit
   typed result path with run/step/export identity and version checks. Do not
   weaken the budget-stop decoder or map an available package to remediation.
4. The shared budget claim helper selects running/verifying only when
   lease_expires_at<=clock_timestamp() (security_agent_budget_admission.sql,
   organization discovery and run selection). Clearing expiry to NULL leaves
   such a parent ineligible. Export settlement requires a current parent lease,
   so the database batch must prove registered restart/reclaim/settle, pending
   backoff without exhausting execution attempts, and independent cleanup after
   cancellation. A direct owner-seeded call to settlement does not prove this.

These findings were sent to the active database implementer before release58
fingerprint freeze. The exact claim transport and settlement scheduling remain
implementation obligations, not verified behavior. They change the next batch's
required tests; no production-availability status is promoted.
