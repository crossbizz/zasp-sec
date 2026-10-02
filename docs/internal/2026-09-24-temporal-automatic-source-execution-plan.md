# Automatic source contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. No nested agents. The controller owns the independent review. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist user-selected trigger rules, carry evaluated policy risk with provenance, and connect committed canonical source changes to duplicate-safe Temporal admission.

**Architecture:** One additive registered extension, numbered77, owns the new contract and exact compatibility changes; old SQL files remain byte-identical. Canonical source mutations insert immutable events in their transaction. Temporal delivers committed events into current-authority SQL matching/admission, sharing the matcher with periodic catch-up and keeping each responder's execution owner explicit.

**Tech Stack:** Go, PostgreSQL/pgx, Temporal Go SDK, React/TypeScript, OpenAPI, Vitest and existing owned PostgreSQL/Temporal fixtures. No new dependency.

**Spec:** `docs/internal/2026-09-24-temporal-automatic-source-design.md`, plus the automatic-source brief and audit report of this date.

## Global constraints

Work only in the linked `cached-runtime-ship-20260917` worktree. The pre-edit4865-file baseline is recoverable. No commits/pushes/provisioning/shared database writes/ledger edits. Do not change historical SQL, accepted75/76 source or their evidence packets. Copy and amend exact effective functions only in77, enumerate each saved signature/owner/ACL and compatibility projection, and include retirement dependencies in the report. Fail on unexpected predecessor text; never normalize whole catalogs.

Controller clarification:75/76 predecessor SQL and evidence stay byte-identical. Narrow Go composition/type integration changes are allowed with affected-boundary tests. The controller checked this plan and authorized grouped implementation on September24.

Count is1..100; window/cooldown1..86400 seconds. Unknown/partial rule shapes fail. Policy-risk vocabulary is low/medium/high/critical; absence is unknown. Manual-only never creates service provenance. Preserve preactivation current-source catch-up, canonical historical IDs/timestamps/receipts, unexpired cooldown across definition edits, SQS paths, shared capacity/budgets/controls and unknown-effect debt. Potential/observed/verified remain distinct; unsupported action/state combinations fail before activation.

These are three dependent implementation groups. The checked-in product remains undeployed throughout; do not enable rules through a registered API before that rule's dispatcher/adapter is ready. A partially implemented77 is not an installable or accepted deliverable. Staged family support must be visible and rejected before activation, with the original unsupported scope recorded.

## Group 1: strict persisted rules through the real API and builder

**Files.** Create `services/platform/securityagent/trigger_rules.go` and `_test.go`; `apps/web/api/security-agent-trigger-rules.ts` and `.test.ts`; `app/features/securityagents/TriggerRuleFields.tsx` and `.test.tsx`; `services/platform/apiserver/security_agent_trigger_rules_postgres_test.go`. Modify `securityagent/types.go`, `securityagent/http.go`, `apiserver/security_agent_repository.go`, `apiserver/workflow_handler.go:847`, `apiserver/security_agent_existing_test_reference.go:27`, `apps/web/api/decoders.ts:1139`, `SecurityAgentsView.tsx` and its tests, `openapi/openapi.yaml` and generated client. Create `migrations/production_temporal_automatic_sources.go`, `migrations/sql/0077_production_temporal_automatic_sources.up.sql` plus focused `.rules.sql`, `.compatibility.sql` fragments, `agentsec-migrate/temporal_automatic_sources.go` and its tests; modify actual migration-command registration in `agentsec-migrate/main.go`.

**Contract.** Existing `trigger_kind`/`trigger_source` remain unchanged for historical routing. Optional `trigger_rules` is a closed discriminated object; no explicit null. Manual rule contains only version/mode. Automatic contains version/mode/cooldown_seconds and exactly the nested rule corresponding to the definition kind:

```json
{"version":1,"mode":"manual"}
{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"high"}}
{"version":1,"mode":"automatic","cooldown_seconds":600,"attack_path":{"state":"verified"}}
{"version":1,"mode":"automatic","cooldown_seconds":600,"runtime":{"decision":"block","action":"http_request","risk":"high","count":3,"window_seconds":300}}
```

Finding family and path state must agree with compatibility `trigger_source`; manual leaves the existing kind/source intact. Runtime action is the evaluated normalized action, not request classification outcome. Runtime risk is optional (omitted means no risk filter); present risk must be one of the four values. No unsupported extra fields, fractional numbers, count0/101, duration0/86401, mixed kind rules or automatic rules missing cooldown. Family/action are trimmed nonempty bounded strings of at most64 bytes. Omission preserves exact old validation and matching.

Expose Go `DecodeTriggerRules(json.RawMessage, string, string) (*TriggerRules, error)` for strict rule parsing and TypeScript `decodeSecurityAgentTriggerRules(value: unknown, kind: string, source: string): SecurityAgentTriggerRules`. The SQL equivalent is private `zasp_temporal77.rules_valid(body jsonb) RETURNS boolean`. The body and audit intent retain the full rules; do not strip the field before calculating a persisted digest. Definition edits use existing disabled-draft/version behavior.

- [ ] Add table-driven decoder RED checks and UI interactions for manual/finding/path/runtime, invalid shapes, limits, legacy omission, create payload and detail save/readback. Extend the actual selected public create/update endpoint tests for both supported handler selections, proving exact persisted body and history digest.
- [ ] Run the grouped RED commands below. Installation capability absence can establish migration RED, but actual valid rule rejection at registered HTTP/SQL and missing UI fields must be observed before calling this group covered.

```sh
go test -C services/platform -count=1 ./securityagent -run '^TestTriggerRules' -v
npx vitest run apps/web/api/security-agent-trigger-rules.test.ts app/features/securityagents/TriggerRuleFields.test.tsx app/features/securityagents/SecurityAgentsView.test.tsx -t 'trigger rules|Trigger rules|manual-only'
go test -C services/platform -count=1 -timeout=8m ./apiserver -run '^TestTemporalAutomaticRulesPostgres$' -v
```

- [ ] Implement strict parsers/types and a small rule-editor component used by Builder and detail edit. Add the optional field to real input/readback schemas and generation. Do not silently populate new defaults into old definitions.
- [ ] Add77 registration/readiness and exact effective SQL validator copies. Initial effective targets include the workflow definition body validator and `zasp_ordered_public62.definition_shape`/`history`, plus the specialized test/export/attack-lab definition validators when those families enter the stage. Save originals and track effective definitions/ACLs. Install all77 fragments atomically only when group3 is ready. Before activation, call a capability check that rejects a rule/action/state combination whose admission adapter is not installed.
- [ ] Re-run only the failing groups for GREEN. Run `npm run openapi:generate`, `npm run openapi:check`, and `npm run typecheck` once after schema/UI changes settle. Record exact versions and outputs. No broad `npm test` or platform-wide Go suite.

Representative contract assertion to implement in the existing endpoint fixture:

```go
// Submit through the selected registered handler; read through its typed API.
// Body must retain the exact rule, version must advance, activation must be draft.
if !bytes.Equal(canonicalJSON(got.Body["trigger_rules"]), canonicalJSON(wantRules)) {
    t.Fatal("persisted rule differs from submitted rule")
}
if got.Activation != "draft" || got.Enabled { t.Fatal("edited rules remained enabled") }
```

## Group 2: policy contributors and authenticated event evidence

**Affected-boundary addendum (controller approved September24).** Installed `zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)` closes both persistent and compiled policy shapes and recomputes SHA256(Rego). Add `0077_production_temporal_automatic_sources.policy.sql` to preserve the exact omitted branch through a saved private compiler and add annotated compilation with the identical Go byte digest (NUL separators use bytea in PostgreSQL). Preserve monitor rollout action override and tool/runtime trigger mapping. Save the exact original compiler signature/owner/ACL (observed definition SHA256 `26cafd835aeb6e7203b913753d39cf9390c29cb6a20594edc637db862d3f9767`), plus the two67 fingerprint functions required for its narrow compatibility projection.77 binds the three effective objects; no whole-catalog normalization or historical migration edits. The installed risk fixture compares SQL and Go output, feeds SQL output to signed consumers, checks omitted compatibility and annotated reconstruction. Include malformed annotation, tamper, combined event digest, cross-protocol no-backfill and revoked/foreign credential cases in the affected batch. Runtime ingestion remains gateway-role DB proof until signed HTTP coverage joins.

**Files.** Modify `services/platform/policy/policy.go`, `policy/runtime.go`, `policy/gateway_cache.go` and focused tests; scoped policy validation/readback in `apiserver/policy_public_handler.go`, `apiserver/workflow_handler.go`, `apps/web/api/decoders.ts` and OpenAPI policy schema. Add `services/runtime-gateway/evaluation_risk.go` and `_test.go`; modify `runtime.go`, `evidence_codec.go`, `production_runtime.go` and focused tests. Modify `services/platform/gatewaycontrol/contract.go`, `postgres.go` and their tests. Add77 `.runtime.sql` fragment and `apiserver/temporal_runtime_risk_postgres_test.go`. Add an optional annotation field to the actual create/edit policy form in `app/features/workflows/ProductionWorkflowViews.tsx` and its test; this component calls the real policy create API at line99. Do not modify the demo `app/features/policies/PoliciesView.tsx`.

**Actual contributor semantics.** The evaluator at `services/runtime-gateway/runtime.go:333-351` visits matching compiled policies. Any matched block resolves block; otherwise any monitor resolves monitor; no match resolves allow. Contributors are the matched block policies when block wins, or matched monitor policies when monitor wins. A monitor does not contribute to resolved block. For the winning set, any missing annotation yields unknown; otherwise choose the highest annotation. Cache-unavailable/expired fail-closed block and no-match allow have no contributors and unknown risk. Keep all existing `MatchedPolicyIDs` for history; store the contributing subset separately in the versioned evaluation evidence.

Optional policy `risk` is strict and versioned with the policy. Include it in compiled digest and the signed bundle only for annotated policies; the omitted old representation and digest remain byte-compatible. Tampering must fail signature/digest validation. Unknown annotations cannot be supplied in arbitrary request classification. New gateway events carry optional closed `evaluation`:

```json
{"version":1,"action":"http_request","agent_id":"pid_...","session_id":"pid_...","contributing_policy_ids":["policy-a"],"risk":"high"}
```

`risk` omitted means unknown. Action/agent/session come from the evaluated normalized ActionContext; contributors/risk come from actual evaluation. Keep request classification unchanged. Persist the annotation in a private77 table keyed by existing canonical gateway event ID, in the same transaction as insertion, so the public gateway table and all historical rows need no new column. New `zasp_temporal77.record_gateway_event(...)` accepts the existing v27 inputs plus evaluation JSON and validates their combined digest. It must not silently fall back to a path that drops evaluation. Existing v27 calls still work unchanged. The authenticated Go repository chooses the new statement only when evaluation is present; old omission uses existing v27 semantics. Source capture can resolve annotation after commit.

- [ ] Add RED cases for block+monitor contributors, two block contributors, unknown winning contributor, unknown losing monitor, no match, cache fail-closed, tampered annotation, exact old digest, evidence disk restart/replay and registered ingestion/readback. Use real policy compilation/evaluation and gateway event codec; transport substitutes only at external IO.

```sh
go test -C services/platform -count=1 ./policy ./gatewaycontrol -run 'Test.*(PolicyRisk|EvaluationRisk)' -v
go test -C services/runtime-gateway -count=1 -timeout=2m . -run 'Test.*(EvaluationRisk|RiskEvidence)' -v
go test -C services/platform -count=1 -timeout=8m ./apiserver -run '^TestTemporalRuntimeRiskPostgres$' -v
```

- [ ] Implement contributor aggregation after decision resolution without changing precedence. Preserve old result cloning, on-disk event/replay and signed material on the omitted path. Add strict new codec/version handling and PostgreSQL atomic annotation+event insertion, scoped current credential verification and unchanged old-event replay.
- [ ] Run the same groups GREEN; inspect logged rows to prove canonical request/evaluation digest, original timestamp and unknown refusal. Regenerate/check public schema only if group2 changes it; do not rerun unchanged group1 installed suite.

Representative evaluator assertion:

```go
// A high block plus an unannotated block is unknown; an unannotated monitor
// does not erase a complete high block contributor set.
if got.Decision != "block" || got.Risk != "" { t.Fatal("unknown contributor was ignored") }
```

## Group 3: atomic source capture, Temporal dispatch and explicit adapters

**Gateway readiness addendum (controller approved September24).** Joined HTTP
diagnostic1 proves the actual gateway principal is ready, but the old public
recovery27 readiness is false through its27-to28-to29 successor chain. Add a
private77 `gateway_ready(c,f)` requiring exact77/predecessor integrity and the
actual registered gateway principal. Repository Ready selects it only when77
is installed; invalid installed state or a probe error cannot fall back. With77
absent, retain27/26 behavior. Public legacy readiness functions and current
Authority/Policy/Record credential checks stay unchanged. Document current
ancestry/live predicate coverage. Group signed authority200, policy no-update204,
omitted27 event, annotated77 event/capture and tampered77 refusal checks. Correct
fixture expiry/signing clocks to whole seconds, without relaxing decoders. Cost
if wrong is gateway access under stale or broken authority; independent review
must inspect this routing boundary.

**Finding writer addendum (controller approved September24).** The actual public risk writer fails its historical audit/export gate on the current61 graph; its body also refuses versions above60. Add a private77 invoker-security copy in `.finding.sql` and route only the typed finding mutation when valid77 is installed. Leave the public writer and global52 readiness untouched. Save exact source/owner/ACL/hash (`b5366f9c295a2b46844dd6b04458cb706cef5e422f2c53c55b487b62bebbfdec`), replace exactly three readiness calls and the local60→61 bound. The new guard requires77/current discovery API principal and explicitly retains the four live audit policy/worker/source-ACL/workflow-ACL predicates; catalog identity remains covered by77's predecessor chain. No new table privileges or definer-security mutation. Add installed discovery-API role, audit/receipt/replay/rollback, tenant refusal and invalid77 no-fallback checks. Registered projection capture can proceed independently.

**Finding-writer compatibility addendum (controller approved September24).**
The installed public `zasp_risk_mutate` still has three audit-export readiness
calls and an exact release ceiling60; source RED2 proves55000 before mutation
under registered61 plus Temporal extensions. Add a private77 copy of that exact
invoker-security function, preserving its saved signature/owner/ACL/source hash.
Replace only the three readiness calls with the current77 guard and the exact
local ceiling60 with61. Keep the public function and shared52 guard unchanged.
Retain all input checks, visibility, tenant RLS, locks, audit, receipts and replay.
Expose the new entry only to the existing discovery API authority, with no
SECURITY DEFINER escalation. Prove the new guard's ancestry retains the required
live audit policy/worker/source predicates; keep explicit predicates where the
ancestry does not cover them. Repository routing may select the new entry only
through installed77 capability: absent can retain the old route, invalid installed
must fail closed. Use the actual API principal for the affected transaction,
replay/audit/receipt and tenant-refusal checks. Cost if wrong is a finding-authority
or audit regression; this amendment requires the same independent task review.

**Files.** Add77 `.sources.sql`, `.matching.sql`, `.admission.sql`, `.compatibility.sql` fragments, metadata/runner/CLI tests, `services/platform/orchestration/automatic_sources.go` and `_test.go`, `agentsec-worker/temporal_automatic_sources.go` and `_test.go`, `apiserver/security_agent_temporal_automatic_sources_postgres_test.go`, `apiserver/security_agent_temporal_automatic_sources_live_postgres_test.go`. Modify production Temporal worker composition/registration and current75 selector integration in `agentsec-worker/temporal_test_selector.go`; amend its effective SQL through77 only. Add narrow deployment contract registration where the existing migration/worker command is selected, without provisioning.

**Interfaces.** `AutomaticSourceRef` contains organization/workspace/environment/event ID. `AutomaticSourceWorkflow(ctx workflow.Context, ref AutomaticSourceRef) error` invokes `AdmitAutomaticSource(ctx context.Context, ref AutomaticSourceRef) error`. Worker repository calls `zasp_temporal77.dispatch(q jsonb) RETURNS jsonb`; result is `{"matched":N,"created":N,"suppressed":N,"after_definition_id":"...","complete":false}` with bound25 per page. The Workflow retains and advances the cursor until complete; durable per-definition consumption makes duplicate pages safe. A Temporal-acceptance acknowledgment means the Workflow owns delivery, not that all definitions were consumed. Completion is recorded only after the final definition page. Cover more than25 matching definitions, restart after a middle page and duplicate retries with no starvation. Private `match(o,w,e,d,event_id,at)` resolves current body/source and returns canonical matching evidence. Both `dispatch` and effective75 current-state selection call it. Relay pages committed pending source events in bounded stable order and starts deterministic workflows; successful durable Temporal acceptance inserts an immutable delivery acknowledgment. Timeout is unknown and retried with the same Workflow ID. No source deletion on timeout, custom claim lease or in-process-only retry state.

Canonical capture uses three named AFTER INSERT/UPDATE triggers on `zasp_risk_findings`, `zasp_risk_attack_paths` and INSERT on `zasp_runtime_gateway_events`. New77 tables store immutable source occurrence, delivery acknowledgment, per-definition consumption, cooldown admissions and matched runtime evidence. Trigger capture performs only local scoped inserts; it never calls match/admit or takes organization budget locks. Event identity includes kind/source/version (runtime event ID); capture source time is separate from delivery time. After commit, dispatch rechecks final path children/current source. Invalid or revoked source cannot create a run. Exact source ID/version evidence is never fabricated from an activation event.

Controller scaling ruling: installation must not eagerly copy every historical
finding/path or a full day of gateway traffic in one unbounded transaction.
Preserve preactivation catch-up through bounded stable-cursor worker pages with
recoverable continuation and the same original source identity/timestamp and
matcher. Triggers capture concurrent new writes. Cost if wrong is missed older
sources or duplicate delivery; verify restart/concurrent-write behavior through
the existing catch-up/replay group. This changes execution shape, not scope.

Runtime access-path ruling: reuse the existing27 index ordered by exact scope,
occurred_at descending and event_id ascending. Traverse scopes with a bounded
next-scope seek, persist runtime scope/time/ID, and read only the recent24h range.
Timestamp ties and older timestamps share the same total page budget (max100).
Empty scopes advance durably. Do not walk lifetime runtime history each wrap or
add a public index for this correction. Finding/path primary-key paging stays
unchanged. Cover equal timestamps across a page boundary, expired-only scopes
followed by recent data, and reconnect continuation. Cost if wrong is missed or
duplicate occurrences at scope/time transitions; Temporal still owns retries
and dispatch, while this cursor records source discovery progress only.

Cooldown admission uses the existing organization admission lock before definition/source locks. Permanent uniqueness is scope+definition ID+canonical event occurrence, independent of definition version. Cooldown key is scope+definition ID+source kind+canonical finding/path ID or runtime session/action/decision pattern, independent of definition version and risk/severity thresholds. Changing thresholds cannot reset suppression. Keep original receipts and record suppressed consumption; replay stays suppressed after cooldown expiry. Distinct later events can admit after expiry. Runtime count is over distinct authoritative event IDs within `[now-window,now]`, grouped by canonical session/agent/action/decision and configured risk; out-of-window/future/unknown-filtered events do not count.

Cooldown deadline ruling: persist the expiry established by each successful
admission. Do not recompute an active window from the current definition's
duration, since a600-to1-second edit would admit again before the original
deadline. Edits affect future admission windows, not the existing deadline.
Cover a shortened-duration edit in the grouped admission checks, preserve
immutable occurrence/audit evidence, and keep a distinct later-event-after-expiry
case. Cost if wrong is an unexpected extra execution after a definition edit.

Controller clarification: page traversal is not an admission receipt. Merely
visiting a disabled/draft/manual-only or currently nonmatching definition cannot
permanently consume a source and defeat later valid preactivation catch-up.
Permanent admission/cooldown suppression receipts belong to eligible matching
decisions. Cover disabled-to-active catch-up of an unchanged current source,
alongside the distinct case where a prior cooldown-suppressed occurrence must
stay suppressed after expiry or definition edits.

Activity sizing ruling:25 is the maximum visited-definition page size. Measure
per-call elapsed time before binding the Temporal Activity deadline; total test
duration does not establish page latency. A smaller fixed quantum is allowed
if a full page exceeds the intended Activity budget, with complete traversal of
more than25 matches and deferred-sweep recovery preserved. Do not cache readiness
across requests or skip authority checks to meet a timeout. Record the chosen
quantum and connected timeout evidence. Cost if wrong is retry starvation from
an oversized page, or unnecessary throughput loss from an undersized one.

- [ ] Add grouped RED checks using the registered writers: `RiskRepository` update for finding, `DiscoveryExecutionRepository.ApplyRiskProjectionInput` for finding/path and `gatewaycontrol.PostgresRepository.Record` for runtime. Inspect zero event on rollback, canonical event after commit, duplicate replay, path final child evidence, missing scope/ID refusal, other tenant refusal and current source revocation. Observe actual registered77 capability/matching absence, not just missing helper compilation.
- [ ] Add matching/admission RED cases for each configured rule, no-match, manual-only, disabled definition, definition/grant revocation, source-version replay, cooldown inside/outside, edits not resetting cooldown, preactivation catch-up, bounded runtime count/window and retained/shared capacity. Add explicit action-family routing assertions before writing each adapter.

```sh
go test -C services/platform -count=1 -timeout=12m ./apiserver -run '^TestTemporalAutomatic(Sources|Matching|FamilyAdmission)Postgres$' -v
go test -C services/platform -count=1 ./orchestration ./agentsec-worker -run '^TestTemporalAutomatic(SourceWorkflow|SourceRelay|Composition)$' -v
go test -C services/platform -count=1 -timeout=8m ./agentsec-migrate -run '^TestTemporalAutomaticSourcesCommand' -v
```

- [ ] Implement atomic capture, current-source matcher, permanent receipts/cooldown and bounded relay/workflow.75 catch-up uses the same matcher when rules exist; omitted rules preserve existing75 selection exactly. Source event and catch-up share receipt identity so neither can duplicate the other.
- [ ] Install the single-test adapter first through current74 service grant and73 admission/start, with no human conversion. Then add each supported automatic family adapter through its actual authority: retained finding response18/21, finding temporary policy22, path policy33, connector revocation23 and runtime isolation24. Preserve the existing executor owner and approval/effect paths; a Temporal dispatcher does not make a retained executor migrated. Ordered62/68 needs its own automatic service grant/admission evidence and canonical identity, never a copied human receipt.57 attack-lab,58 export and59 webhook are explicit remaining adapter stages until their actual automatic eligibility/owner is proven. Reject new-rule activation for unsupported combinations with named capability reason. Legacy omitted-rule execution is unchanged. Record family-stage acceptance separately; do not call full35..38d complete from the first adapter.
- [ ] Run the failed groups GREEN, then freeze source and run one connected writer -> event -> Temporal dispatcher ->74 execution -> typed/HTTP readback fixture. Use the existing owned database/local Temporal helpers; the native/provider transports remain controlled and labeled. Add registered retained-family delivery checks for adapters changed in this stage without rerunning all accepted executor suites.

```sh
go test -C services/platform -count=1 -timeout=15m ./apiserver -run '^TestTemporalAutomaticSourcesLivePostgres$' -v
```

- [ ] Produce an exact source manifest before nested builds, keep source frozen until they exit and join all owned processes. Retain failed attempts and final outputs. Compare against the4865-file overlay baseline and verify all pre77 SQL byte hashes unchanged. Update the audit report with actual changed signatures/catalog objects, source hashes, commands/results, failed attempts, owner/family acceptance and open deployment/FGA gates. Freeze the coherent stage for the controller's independent review; no commit or publication.

## Self-check before coding

The plan implements the approved three-group sequence. It preserves missing-risk uncertainty, actual decision precedence, shared matcher, canonical transactional emission, permanent dedup separate from cooldown and explicit family staging. Exact installed compatibility projections are derived from the existing registered fixture and saved effective object definitions; any required object outside the enumerated definition/event/admission boundary needs a recorded affected-boundary reason before amendment.

No task changes Temporal/OpenFGA internals or claims deployed evidence. The controller consistency check precedes production edits. Use inline execution under the existing one-owner instruction; do not create another task or agent.

## Connected gateway readiness amendment

Controller approved the exact optional `zasp_temporal77.gateway_ready(text,text)`
boundary after `sources-runtime-http-diagnostic1.log`: actual gateway role reports
recovery readiness false, runtime principal true, no SQL exception. Public27
readiness delegates the old28/29 successor chain; it does not select the private
61/Temporal ancestry. Leave every public readiness function unchanged.

Gateway `PostgresRepository.Ready` first probes77 installation. A present77 uses
only the compiled checksum/fingerprint and gateway-ready contract. False/error,
including a missing function in a present schema, fails closed. Only absence
retains the unchanged27/26 compatibility sequence. Authority, Policy and both
Record protocols retain their existing current credential checks and SQL.

The new gate requires77 catalog integrity plus76→75→74→earlier Temporal
predecessors and67 base integrity. `67.base_ready` requires exactly61 public
versions, exact61 checksum/metadata, scope authority, private61 predecessor60
readiness and the portable registered base fingerprint. That fingerprint retains
the registered61 and public60 catalog ancestry. The private predecessor chain
retains its security predicates; this change does not rewrite them. The new
gate additionally evaluates live `zasp_runtime_principal_ready` for the actual
gateway session. This is catalog and principal readiness, not a substitute for
the credential authority called for every request or evidence of deployed
gateway health.

Grouped tests: six optional-install routing cases, affected original27/26 tests,
then real signed HTTP Authority200, policy no-update204, annotated77 capture,
omitted27 capture without risk fabrication, transaction rollback, exact replay,
signature tamper, catalog-tampered77 refusal on all affected routes and revoked
credential refusal. Seed whole-second credential expiry to satisfy the unchanged
authority decoder. SQL installation first derives the new exact catalog pin;
the initial old-pin failure is a compilation checkpoint, not behavior evidence.

## Matcher snapshot clarification

The shared matcher is private source selection, not admission authorization.
It returns the final committed canonical source plus ordered child evidence and
a digest over that snapshot. Finding/path legacy identity digests remain
separately named for existing adapter interoperability; they are not payload
proof. Bind the full snapshot in the eventual immutable77 admission receipt.
Tests must compare returned payload/digests across valid same-version source or
child changes, since a Boolean match assertion cannot prove this contract.

## Runtime catch-up access path

Controller approved reusing the existing27 index on
`(organization_id,workspace_id,environment_id,occurred_at DESC,event_id ASC)`.
Scan one scope at a time, finding the next scope through the gateway-device
primary-key prefix. Persist runtime scope/time/ID. For continuation, seek
remaining IDs at the same timestamp, then older timestamps with the remaining
page budget. Filter the24h range in those index seeks, not after walking lifetime
history. Empty scopes advance durably; findings/path keep their primary-key
tuple cursor. No public index build or historical rewrite is needed. The cursor
is scan progress, not a lease/dispatch/retry engine.

## Runtime envelope clarification

Keep omitted evaluation compatible with historical gateway events. At the
authenticated ingestion boundary, reject explicit `evaluation:null` and duplicate
evaluation fields that could erase an annotation. Pointer decoding bypasses the
nested evidence decoder for null, so cover these with raw signed-envelope tests
in the affected contract batch. Preserve existing omitted-event acceptance and
do not rewrite historical records. This closes an evidence-validation gap; it
does not require testing the JSON library itself.

## Admission and bounded continuation details

Store each successful admission's cooldown deadline, not a timestamp evaluated
against the latest rule duration. A600→1 edit must preserve the original active
window. Immutable occurrence receipts survive edits and expiry separately. A
pre77 source receipt is already consumed under current scoped authority: return
its original run without invoking75's incompatible current-version replay branch
or rewriting its receipt/audit.

The first adapter is77 occurrence authority ->75 admission ->73 start ->74 test
execution for findings and observed/verified paths. A configured-run row guard
requires the77 decision for automatic callers, while existing API human authority
remains separate. Other automatic family/source combinations remain gated and
must not be reported as accepted.

Next executable group adds77 definition pages bounded to25 visited definitions,
with a strict cursor and capacity deferral returned to Temporal. Finish later
pages before retrying deferred work. Configured periodic catch-up pages current
canonical sources and calls the same occurrence authority. Disabled/draft/manual
or nonmatching visits never create occurrence receipts. Dedicated source and
configured-catch-up Workflows own retries and continuation. Omitted-rule75
Schedules retain their current behavior. Production Go composition distinguishes
absent77 from present-invalid77 and must not downgrade after a failed probe or
readiness check. Add focused page, Workflow, relay and composition RED/GREEN
checks, then connected delivery/restart; do not repeat unchanged successful
source/matcher suites.

Measured page work fixes the initial quantum at5 visited rows, beneath the25
contract bound. Local five-admission pages stayed below12s; native Activities
use30s StartToClose with25s database calls. The Workflows finish every cursor
page before a deferred-capacity sweep and Continue-As-New after100 pages,
carrying cursor/retry state. No SQL claim lease or cross-request readiness cache.

The source relay commits attempt ordering before Start and only ACKs exact
durable acceptance. The adapter verifies successful handles and, on the specific
AlreadyStarted error, binds described current/root runs plus immutable start
input/type/queue and the previous Continue-As-New close event. Completed owned
workflows still own their source; unavailable history fails closed.

Connected checks use the verified retained local Temporal1.32.0 Compose server
with unique namespaces. Separate child processes test post-acceptance ambiguity
then production execution, configured periodic replay, and a genuinely later
source after actual settlement/cooldown. Add mounted HTTP typed readback with
the action-details version header, asserting exact parent/state/test link and
verification fields. A separate page-only native worker fixture crashes only
its directly spawned test binary after a completed first5-row Activity and
before the next page. Replacement must retain the logical Workflow/run ID and
finish all26 actual activated definitions with one receipt each. This isolates
middle-page recovery from production-constructor consumption. No retained server
or volume restart, cleanup or availability claim is authorized by these tests.
