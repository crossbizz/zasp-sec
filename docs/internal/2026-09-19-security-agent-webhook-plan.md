# M7A-24 Signed Response Webhook Implementation Plan

> For agentic workers: use `superpowers:executing-plans` to execute this plan task by task. Use `superpowers:subagent-driven-development` only after explicit delegation authorization. Steps use checkboxes. This document authorizes no implementation by itself.

**Goal:** Deliver an operator-approved, immutable, redacted and HMAC-signed current-run evidence handoff to a saved tenant-scoped destination, with honest durable status across restart.

**Architecture:** Add a response-delivery authority after release 58, separate from v35's integration-test records. Reuse the production pinned HTTPS transport with a version-aware secret adapter and a dedicated worker. Keep unknown post-dispatch outcomes terminal and visible, with a stable receiver deduplication identity and no automatic resend.

**Tech Stack:** Go 1.25.6, PostgreSQL registered functions/RLS, AWS Secrets Manager SDK, existing HTTP/TLS transport, OpenAPI, TypeScript/React, Node 22.23.1 and npm 10.9.8.

**Spec:** `docs/internal/2026-09-19-security-agent-webhook-design.md`.

## Global Constraints

- Implementation begins only after approval to execute; this packet is a plan.
- Preserve every release-58 SQL file and checksum. Candidate release 59 must be unclaimed when execution starts.
- No action-time URL, arbitrary payload, secret reference, signing version, headers, or retry override is accepted.
- The approval floor is always `operator`, including autonomous definitions and schedules.
- Payload maximum is 16 KiB; evidence selection is nonempty, maximum 8; initial source kinds are `manual` and `run_audit`.
- Provider timeout is at most 10 seconds; dispatch lease is 30 seconds; at most 3 pre-dispatch claims; no automatic resend after dispatch.
- Preserve a stable delivery ID. Do not claim exactly-once receiver effects, receiver verification, or downstream remediation.
- Do not turn controlled local evidence into a production availability claim. Keep M7A-23 dependencies and SHIP-GATE explicit.
- Preserve inherited dirty files. Own only listed files during each packet, record before/after hashes, and request review before crossing a packet boundary.
- Use `apply_patch`; do not commit, merge, push, or alter shared runtime/deployment state without the separate authorization required for that action.

## Execution setup and conventions

Work in the existing shipping worktree, not another checkout of the same dirty files. Read the design and the task-card/TSV rows first. Record `git status --short`, full SHA-256 manifests for affected source trees, release identity, and tool versions. Check migration slot 59. A collision is a re-planning gate, not permission to rename another migration.

Use this shell prefix for commands below:

```sh
export PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
node --version
npm --version
/opt/homebrew/bin/go version
```

Expected versions: v22.23.1, 10.9.8, go1.25.6. Compile/test with `/opt/homebrew/bin/go -C services/platform test -race -count=1 ...`. Database selectors must run through the owned-container proof added in Task 2, with installed release identity verified and zero skips. A skipped PostgreSQL test is not GREEN. The harness creates uniquely named containers/databases, preserves failure logs, joins every owned process, and removes only its exact recorded resources. Never send owner credentials to application binaries.

All proposed exported names and schemas below are the implementation contract. Existing product canonical ID/digest validators remain authoritative; no second, looser grammar is introduced. Test fixture identifiers must come from registered product creation paths. New test helpers live in the named packet's test files and are not production bypasses.

## Task 1: Closed response contract, payload, and version-aware signing boundary

**Ownership:** create `services/platform/securityagent/response_webhook.go` and `response_webhook_test.go`; create `services/platform/apiserver/security_agent_webhook_transport.go` and `_test.go`; modify `services/platform/apiserver/finding_ticket_webhook.go` only to expose the shared pinned client to the response method. Create `services/platform/webhooksecret/resolver.go` and `resolver_test.go` for the version-aware SDK adapter. Do not move or change the v35 resolver's default behavior.

**Interfaces:** package `securityagent` produces the following wire types and encoder; package `webhooksecret` produces `Resolver.ResolveVersion(ctx context.Context, organizationID, workspaceID, environmentID, reference, version string) ([]byte, error)`. The resolver constructor accepts the existing AWS Secrets Manager client interface, webhook prefix and bounded timeout. Validate canonical scope identifiers and the existing reference grammar, rejecting traversal. Derive the name as `<webhook-prefix>/<organization_id>/<workspace_id>/<environment_id>/<reference-suffix>`; never use the unqualified v35 namespace as a fallback. Validate the opaque version, use `GetSecretValue` with `SecretId` and `VersionId` (no `VersionStage`), verify returned VersionId and key length 32..4096, and clear rejected bytes. The transport method takes the immutable bytes and owns no source lookup.

```go
type ResponseWebhookEvidence struct {
    SourceKind string `json:"source_kind"`
    SourceID string `json:"source_id"`
    SourceVersion int64 `json:"source_version"`
    AssociationDigest string `json:"association_digest"`
}
type ResponseWebhookPayload struct {
    SchemaVersion int `json:"schema_version"`
    Type string `json:"type"`
    DeliveryID string `json:"delivery_id"`
    OrganizationID string `json:"organization_id"`
    WorkspaceID string `json:"workspace_id"`
    EnvironmentID string `json:"environment_id"`
    RunID string `json:"run_id"`
    StepID string `json:"step_id"`
    PlanHash string `json:"plan_hash"`
    Evidence []ResponseWebhookEvidence `json:"evidence"`
}
func EncodeResponseWebhookPayload(ResponseWebhookPayload) ([]byte, string, error)
```

Use typed fields in exactly that order, `json.Marshal`, full structural validation before marshal, and a sha256 digest of the returned bytes. Validation does not claim repository membership. Declare `ResponseWebhookReceipt` with `Outcome string` (`acknowledged`, `failed`, `uncertain`) and `ErrorCode string` in `securityagent`. In `apiserver`, expose `DeliverSecurityAgentResponse(ctx context.Context, destination, deliveryID, digest string, payload, secret []byte) (securityagent.ResponseWebhookReceipt, error)` on `findingTicketWebhook` and extend `ProductionFindingTicketWebhook` with that method. An error before network invocation is pre-dispatch failure; once invocation begins, any transport error is conservatively uncertain. The secret adapter accepts VersionIds only matching `^[A-Za-z0-9-]{32,64}$`.

- [ ] Write table-driven `TestSecurityAgentWebhookPayloadClosedCanonical` including exact bytes/digest, empty/9-item/duplicate/unsorted selection, unknown kind, invalid canonical identifiers/digests, size overflow, and secret/prompt/title sentinels. Start with the full literal JSON from the design, including its canonical unprefixed 64-lowercase-hex manual source ID, as a golden expected byte string; a separately written JSON-shaped fixture must not replace the actual encoder under test.
- [ ] Add `TestSecurityAgentWebhookVersionedSecret` with a stub capturing the AWS input. The key assertion is:

```go
if aws.ToString(captured.VersionId) != approvedVersion || captured.VersionStage != nil {
    t.Fatalf("secret version is not pinned: %#v", captured)
}
```

Test provider version mismatch, missing version, malformed scope/reference/version, key length, cancellation, and zero SDK calls on malformed local inputs. Require same-reference different-version secrets to return distinct actual bytes in the test. With the same reference in two valid tenant scopes, assert two distinct provider SecretIds and tenant-specific bytes; a second-tenant caller must never resolve the first tenant's path.
- [ ] Add `TestSecurityAgentWebhookTransport` exercising the actual response method with exact HMAC header, delivery ID, payload digest, empty 204 only, nonempty204, 200/302/429/500, oversized provider text, and network interruption. Use a captured receiver request and independently calculate `hmac.New(sha256.New, key)` over those captured bytes.
- [ ] Run RED: `/opt/homebrew/bin/go -C services/platform test -race -count=1 ./securityagent ./apiserver ./webhooksecret -run '^TestSecurityAgentWebhook(Payload|VersionedSecret|Transport)'`. First failure may be missing symbols; require behavioral RED for rejection/outcome assertions before considering the feature implemented.
- [ ] Implement only the listed encoder, resolver, and transport. Preserve existing pinned DNS/CIDR/TLS rules; shared transport helpers must retain all v35 tests. Never log the input payload, key, or provider response body.
- [ ] Run GREEN plus existing `TestFindingTicketWebhook|TestProductionFindingTicketWebhook|TestIntegrationWebhook` selectors. Inspect diff/hashes and obtain security-boundary review before Task 2.

## Task 2: Additive registered PostgreSQL authority and saved destination binding

**Ownership:** create `services/platform/migrations/sql/0059_production_security_agent_webhooks.up.sql` and `.down.sql`, `services/platform/migrations/production_security_agent_webhooks.go`, and `_test.go`; modify `migrations/migrations.go` and `agentsec-migrate/main.go` only for additive registration/dispatch. Create `apiserver/security_agent_webhooks_repository.go`, `_test.go`, and `security_agent_webhooks_postgres_test.go`. Modify `apiserver/security_agent_existing_test_reference.go` and its tests only to admit and closed-validate `response_webhook_destination`. Create `deploy/production/security-agent-webhook-runtime.mjs` and `.test.mjs` as the owned compiled-test runner. Existing integration configuration validation in `apiserver/workflow_handler.go` receives the optional pinned signing-version validation; its version field is secret metadata, not a raw key.

**Interfaces:** repository methods `AcceptAndPrepareResponseWebhook`, `ClaimResponseWebhook`, `BeginResponseWebhookDispatch`, `CompleteResponseWebhook`, `ExpireResponseWebhooks`, `ClaimResponseWebhookSettlements`, `SettleResponseWebhookParent`, and `GetResponseWebhook` use `context.Context` plus typed inputs, return typed records/errors, and call registered functions with bind parameters only. Define `ResponseWebhookScope` as organization/workspace/environment strings, `ResponseWebhookClaim` as delivery ID, scope, token, generation, expiry, private destination/key version, payload/digests and run/step IDs. `ResponseWebhookStatus` contains only the public fields listed in the design. Inputs must carry authenticated principal/session authority where called on behalf of a user; worker tokens cannot impersonate that caller.

The repository interface lives in `apiserver/security_agent_webhooks_repository.go`. Define `ResponseWebhookAuthority` with `Scope ResponseWebhookScope`, `PrincipalID string`, `SessionID string`. Define `ResponseWebhookAcceptance` with `Claim SecurityAgentRunClaim`, `WorkerID`, `LeaseToken`, `ApprovalID`, `AuditID`, `CorrelationID`, `IdempotencyKey`, and `DestinationID` strings, `ApprovalExpiresAt time.Time`, `Submission SecurityAgentPlannerSubmission`, and `Evidence []securityagent.ResponseWebhookEvidence`. The submission carries the exact input/output digests, model, policy version, summary, action and target used by the current planner acceptance contract. The method derives step ID, plan hash, definition/version and scope from the fenced claim and registered transaction result; callers cannot supply them. `ResponseWebhookFence` has `Scope ResponseWebhookScope`, `DeliveryID`, `Token` strings, `Generation int64`. `ResponseWebhookRead` has `Authority ResponseWebhookAuthority` and `AgentID`, `RunID`, `DeliveryID` strings. The implementation contract is:

```go
type ResponseWebhookRepository interface {
    AcceptAndPrepareResponseWebhook(context.Context, ResponseWebhookAcceptance) (ResponseWebhookStatus, error)
    ClaimResponseWebhook(context.Context) (ResponseWebhookClaim, bool, error)
    BeginResponseWebhookDispatch(context.Context, ResponseWebhookFence) error
    CompleteResponseWebhook(context.Context, ResponseWebhookFence, securityagent.ResponseWebhookReceipt) (ResponseWebhookStatus, error)
    ExpireResponseWebhooks(context.Context, int) (int, error)
    ClaimResponseWebhookSettlements(context.Context, string, string, int, int) ([]ResponseWebhookSettlementClaim, error)
    SettleResponseWebhookParent(context.Context, ResponseWebhookSettlementClaim, string, string, string, string) (ResponseWebhookSettlementResult, error)
    GetResponseWebhook(context.Context, ResponseWebhookRead) (ResponseWebhookStatus, error)
}
```

The dispatch worker's `ClaimResponseWebhook` is authorized by its restricted database role, not a caller-supplied tenant. It returns at most one eligible scoped row; `false, nil` means no work. `ExpireResponseWebhooks` rejects batch sizes outside 1..100. The normal Security Agent worker alone can claim terminal parent settlements in bounded batches of 1..25 and settle with the exact unexpired token/generation. Cancellation remains cancellation, terminal replay returns the same result, and a stale claimant cannot overwrite a newer or terminal parent. The settlement role has no secret resolver or dispatch function grant. All returned records are closed-decoded and canonical-validated before use.

SQL functions, under a single owner, are named `zasp_accept_security_agent_webhook_plan`, `zasp_claim_security_agent_webhook`, `zasp_begin_security_agent_webhook_dispatch`, `zasp_complete_security_agent_webhook`, `zasp_expire_security_agent_webhooks`, `zasp_claim_security_agent_webhook_settlements`, `zasp_settle_security_agent_webhook_parent`, and `zasp_get_security_agent_webhook`. Follow current registered-function search-path, grants, owner, RLS and release-identity conventions. The action-specific accept function takes the same fenced planning claim, worker/lease, input/output digests, model, policy version, candidate summary, approval ID/expiry, audit and correlation authority required by `AcceptSecurityAgentPlannerCandidate`, plus the closed response destination/evidence inputs. In one database transaction it checks the live planning lease and settled model/output receipt, validates the same-scope destination and exact stored evidence membership, derives the plan/step identity, creates the planner receipt/plan/step/approval snapshot, encodes the immutable payload, and inserts its delivery record. It does not trust caller JSON. Any error rolls back both planner acceptance and delivery preparation. Do not call generic acceptance first, expose a separately callable prepare gap, or obtain membership through an owner-side fixture insert.

- [ ] Add `TestSecurityAgentWebhookAuthorityPostgres` with registered API-created integrations, definition/control history, trigger/run sources, settled model reservation, plan and approval. Install the exact release58 predecessor then candidate59. Prove a real second organization can prepare its own valid response before rejecting cross-org access. Repeat for workspace/environment. Two live sessions for the same principal and scope must each complete a positive authorized read; reject a revoked/stale session and any session attempting a resource outside its authorized scope. Do not introduce origin-login-session ownership: same-principal sessions with identical live scope share the principal's read authority.
- [ ] Add `TestSecurityAgentWebhookApprovalPostgres`: supervised and autonomous definitions both require operator approval; stale/revoked/expired approval, changed control/definition/integration/key version, disabled destination, cancelled run and kill switch all refuse before dispatch. Preserve exact payload and selection digests through approval.
- [ ] In `TestSecurityAgentWebhookApprovalPostgres`, inject failure after candidate validation and after plan/step construction inside the registered accept path. Each failure must leave zero accepted planner receipts, steps, approvals and delivery rows. Reject stale/foreign planning leases and input/output/model values that do not match the settled provider reservation. Treat planner `PolicyVersion` and provider `cost_policy_version` as separate authorities: the planner policy is bounded and replay-consistent in the atomic planner receipt, never compared to the pricing policy. Lose the successful SQL response, replay the same acceptance, and require the same plan, step, approval and delivery identities with one durable row apiece.
- [ ] Add `TestSecurityAgentWebhookIdempotencyPostgres` and `TestSecurityAgentWebhookLeasePostgres`. Race two registered claims using separate connections; count successful claims and stored rows:

```go
if successfulClaims != 1 || deliveryRows != 1 {
    t.Fatalf("claim fence failed: claims=%d rows=%d", successfulClaims, deliveryRows)
}
if replay.DeliveryID != prepared.DeliveryID || replay.PayloadDigest != prepared.PayloadDigest {
    t.Fatal("replay changed immutable handoff")
}
```

Vary every identity dimension, use a new idempotency key for the same action, and reuse one key for altered input. Check stale token/generation, terminal overwrite, 3-claim exhaustion, expired pre-dispatch recovery, and expired dispatch -> uncertain with no new claim.
- [ ] Add `TestSecurityAgentWebhookReleaseCyclePostgres`: 58->59->58->59 with safe down refusal when durable webhook data exists, exact predecessor identities/functions retained, no release58 SQL edits, direct table grants denied, unknown checksum/fingerprint startup refusal. Down must not destroy delivery evidence.
- [ ] RED: `node deploy/production/security-agent-webhook-runtime.mjs --group authority`. Build the harness first so missing application behavior yields a test failure, not an environment skip. It compiles Go test binaries, installs the selected migration in unique owned PostgreSQL containers, captures JSON events, and rejects any unexpected skip. No source-injected function bodies are allowed in this proof.
- [ ] Implement row constraints and registered transitions. Use this transition predicate as the dispatch boundary, joined to current run/definition/approval/destination authority inside the same transaction:

```sql
UPDATE zasp_security_agent_webhook_deliveries
SET state = 'dispatching', dispatch_started_at = clock_timestamp()
WHERE organization_id = p_organization_id
  AND workspace_id = p_workspace_id AND environment_id = p_environment_id
  AND delivery_id = p_delivery_id AND state = 'leased'
  AND lease_token = p_lease_token AND lease_generation = p_generation
  AND lease_expires_at > clock_timestamp()
RETURNING delivery_id;
```

Zero rows refuses send. Store signature inputs only, never signatures or raw keys. Immutable-field constraints apply to all update paths. Registered completion cannot overwrite terminal or expired/fenced state.
- [ ] GREEN: rerun authority group, prior `TestSecurityAgentExportNonExportRoutePostgres` siblings on release57 and current58, then the candidate59 compatible regressions. Record installed identities separately; never report a release58 proof as a59 proof. Review SQL/grants before Task 3.

## Task 3: Real planner preparation, dedicated dispatch and restart settlement

**Ownership:** create `agentsec-worker/security_agent_webhook_planner.go`, `_test.go`, `security_agent_webhook_runtime.go`, `_test.go`, `security_agent_webhook_production.go`, `_test.go`, `security_agent_webhook_process_postgres_test.go`; modify `agentsec-worker/security_agent_runtime.go`, `security_agent_planner.go`, `security_agent_planner_test.go`, `runtime_config.go`, `runtime_config_test.go`, `production_runtime.go`, and `main.go` only for the action-specific evidence parameters, atomic acceptance/settlement hook and the dedicated mode. Modify `securityagent/builtin_actions.go` and `action_readiness.go` only for production typed parameters/metadata while retaining component-test coverage. Task 2 repository files are frozen; any correction returns to that owner.

**Interfaces:** define `ResponseWebhookProcessor.RunOnce(context.Context) (bool, error)`, constructed from a typed repository, `ResolveVersion` secret resolver and `DeliverSecurityAgentResponse` transport. The planner adapter accepts only repository-loaded source descriptors and the saved definition destination binding; it returns the closed action parameters and invokes `AcceptAndPrepareResponseWebhook`, never generic acceptance followed by preparation. The normal security-agent run loop uses `ClaimResponseWebhookSettlements` and `SettleResponseWebhookParent` to recover terminal delivery facts and settle the parent step. It never invokes the component in-memory backend as production and never gets secret or HTTP access through settlement.

- [ ] Add `TestSecurityAgentWebhookPlanner` with unknown/action-time URL, body, secret, signing-version and header keys. Assert no reservation/delivery on invalid parameters. Assert exact canonical source membership and budget/model settlement idempotency on accepted output.
- [ ] Add planner regression cases proving non-webhook actions still reject unexpected evidence parameters, while `send_response_webhook` accepts only its closed canonical selection and invokes exactly one atomic accept call. A failed or lost-response accept must not create a second plan, approval or delivery.
- [ ] Add `TestSecurityAgentWebhookProcessor` with injected counted dependencies. Cover every design state transition and the following mandatory side-effect invariant:

```go
_, err := processor.RunOnce(ctx)
if err == nil || secretCalls != 0 || httpCalls != 0 {
    t.Fatalf("unauthorized path had side effects: err=%v secret=%d http=%d", err, secretCalls, httpCalls)
}
```

Apply this assertion to claim refusal; apply `httpCalls == 0` and cleared key bytes to revocation between secret read and begin-dispatch. Terminal replay has no error and both counters zero. Provider refusal after dispatch is failed; timeout and lost connection are uncertain; neither can be reclaimed.
- [ ] Add `TestSecurityAgentWebhookRestartPostgres` using owned worker processes and a real registered database. Name kill points `prepared`, `claimed`, `secret_resolved`, `dispatch_committed`, `http_ack_before_db`, `db_ack_before_response`, `terminal_read`. Receiver request counts must be zero for prepared/claimed pre-send kill, zero or one for dispatch boundary depending on controlled breakpoint, exactly one at HTTP-ack and terminal points, and unchanged after restart for dispatch ambiguity. Expected restart states follow the design table, not a blanket retry policy.
- [ ] Extend the restart proof with `delivery_terminal_before_parent_settlement` and `parent_settlement_committed_before_response`. Kill the normal worker at both points, then require a fenced claim after lease expiry, one parent transition, stable lost-response replay, preserved cancellation, and zero additional secret, HTTP, approval or model calls.
- [ ] RED: `node deploy/production/security-agent-webhook-runtime.mjs --group dispatch`. Require actual process exit and restart, not two method calls on one object. Introduce breakpoints only in proof adapters; production control inputs cannot expose them.
- [ ] Implement this sequence, with each database transition checked before proceeding:

```text
expire stale dispatches -> uncertain
claim approved prepared/pre-dispatch-expired record
validate immutable payload digest
resolve exact key version (defer clear)
commit begin-dispatch with fresh authority check
invoke pinned transport once
complete with bounded independent context and matching token/generation
read durable terminal result for parent settlement
```

If completion response is lost, read the record before any retry. If no durable acknowledgement exists after dispatch expiry, settle needs-human/uncertain. Parent cancellation remains cancelled even if a private acknowledgement receipt exists.
- [ ] GREEN: dispatch group plus unit selector below, existing export settlement/planner and attack-lab runtime siblings. Review crash evidence and side-effect counters before Task 4.

## Task 4: Public configuration, approval, status and UI contract

**Ownership:** modify `apiserver/workflow_handler.go`, `apiserver/workflow_handler_test.go`, `agentsec-api/production_runtime.go`; create `apiserver/security_agent_webhook_handler.go`, `_test.go`, `agentsec-api/security_agent_webhook_composition_test.go`. Modify `openapi/openapi.yaml`, regenerate `apps/web/api/generated.ts`, modify `apps/web/api/decoders.ts`, `decoders.security-agent-actions.test.ts`, and `decoders.security-agent-approval-context.test.ts`. Modify `app/features/securityagents/SecurityAgentsView.tsx`, `ApprovalContext.tsx`, `ActionDetails.tsx`; create `webhook-api.ts`, `webhook-api.test.ts`, and `WebhookActionDetails.test.tsx` there. Modify `app/features/workflows/ProductionWorkflowViews.tsx` and `ProductionWorkflowViews.test.tsx` only for saved signing-version configuration. Do not alter demo seeded success to stand in for this path.

**Interfaces:** extend definition controls with `response_webhook_destination: {integration_id: string; integration_version: number}`. Extend the production action parameter union with `{destination_id: string; evidence_selection: ResponseWebhookEvidence[]}`. Add `GET /api/v1/security-agents/{id}/runs/{run_id}/webhook-deliveries/{delivery_id}` as defined in the design. UI reads are through generated/validated API helpers, not raw fetch. Status accepts only prepared/leased/dispatching/acknowledged/failed/uncertain/cancelled and `receiver_verification: "unproven"`.

- [ ] Add `TestSecurityAgentWebhookPublicAPI` for closed request schemas, catalog disabled when capability absent, saved destination selection, approval digest/key-version rendering, exact same-scope status, and redacted errors. Assert response bodies exclude sentinel URL/key/ref/provider text/raw evidence. Reject foreign run/agent/delivery combinations and revoked sessions.
- [ ] Add decoder and `WebhookActionDetails` tests for all seven states, no guessed success on pending/malformed status, unknown-state refusal, and exact user copy:

```ts
expect(screen.getByText("Delivery outcome unknown")).toBeVisible();
expect(screen.getByText("The request may have been received. No automatic resend was attempted.")).toBeVisible();
expect(screen.queryByRole("button", { name: /resend/i })).not.toBeInTheDocument();
expect(screen.queryByText(/remediated|receiver verified|exactly once/i)).not.toBeInTheDocument();
```

- [ ] RED: `/opt/homebrew/bin/go -C services/platform test -race -count=1 ./apiserver -run '^TestSecurityAgentWebhookPublicAPI$'`; run `npm test -- app/features/securityagents/webhook-api.test.ts app/features/securityagents/WebhookActionDetails.test.tsx apps/web/api/decoders.security-agent-actions.test.ts apps/web/api/decoders.security-agent-approval-context.test.ts app/features/workflows/ProductionWorkflowViews.test.tsx`. `npm run openapi:check` must fail until generated types match the updated source.
- [ ] Implement authenticated handler/catalog wiring, exact OpenAPI schemas (`additionalProperties: false`), regenerate client types with `npm run openapi:generate`, then extend strict decoders and UI. Hide private key references even from delivery status; show only approved version/digests and saved destination identity.
- [ ] GREEN: `npm run openapi:lint`, `npm run openapi:check`, `npm run openapi:test`, named UI tests, `npm run ui-api:check`, `npm run build`, and public API Go tests. Review public wording against all state outcomes before Task 5.

## Task 5: Fail-closed rollout/readiness and controlled connected browser proof

**Ownership:** create `agentsec-api/security_agent_webhook_readiness.go` and `_test.go`; create `deploy/production/security-agent-webhook-rollout.mjs`, `.test.mjs`, `security-agent-webhook-release-fixture.mjs`; create `deploy/staging/product/templates/security-agent-webhook.yaml` and `security-agent-webhook-network.yaml`; modify `deploy/staging/product/values.yaml`, `values-saas.yaml`, `values-customer-edge.yaml`, `values-single-tenant.yaml` for disabled-by-default settings. Modify `agentsec-api/production_runtime.go` only through the Task 4 owner. Create `scripts/security-agent-webhook-mounted-browser.mjs` and `.test.mjs`, `agentsec-api/security_agent_webhook_browser_process_test.go`; modify `scripts/production-combined-e2e.mjs` and `.test.mjs` only for this scoped harness. Create evidence only under `docs/internal/security-agent-webhook-20260919/`. Ledger changes are limited to M7A-24/M7A-23 evidence statements in `docs/internal/launch-execution-20260919/tasks.md` and `docs/internal/implementation_production_availability_v1.5.tsv` after verified results.

**Interfaces:** readiness consumes exact candidate schema checksum/fingerprint, dedicated worker mode and role, saved destination binding, pinned secret-version support, approved CIDRs and TLS/egress contract. The rollout renderer emits a disabled default and refuses partial enabled configurations. `security-agent-webhook-runtime.mjs --group {authority,dispatch,public,all}` and mounted-browser harness emit source-bound JSON manifests, logs and checksums. Any proof fixture that supplies a controlled identity/model/secret/receiver must list that boundary in its output.

- [ ] Add `TestSecurityAgentWebhookReadiness` and Node rollout RED cases for missing/incorrect schema identity, worker role, secret version, CIDRs, active worker proof, unsafe TLS configuration, and enabled-with-partial-config. Require disabled public catalog, not merely a warning log.
- [ ] Add a connected browser test that creates integration and definition through the real API, binds controls, runs the real repository-loaded plan, rejects arbitrary URL parameters, approves as operator, and shows acknowledged handoff. Capture the trusted receiver's exact bytes, independent HMAC verification, stable ID and count. Test a second real organization and a second valid session using their own positive flows before cross-tenant/token negatives.
- [ ] Add browser unknown-outcome proof: receiver consumes the request then connection/result is lost at a controlled boundary; restart owned API and worker, verify `Delivery outcome unknown`, no resend control, and unchanged receiver count. Secret/prompt/title/URL sentinels must not occur in API bodies, DOM, logs or retained public artifacts. Keep private proof credentials out of screenshots and logs.
- [ ] RED: run Node rollout/browser harness tests plus `--group public`; the connected harness must fail if the production route is absent or substituted with demo data.
- [ ] Implement disabled-by-default rollout, real readiness composition, and exact registered browser setup. Use owned disposable PostgreSQL, controlled identity/model/secret adapters and trusted TLS receiver, with explicit shutdown/join handling. Do not weaken CIDR/TLS checks in shipped code for local browser execution.
- [ ] GREEN: run the full grouped selector below, browser proof, OpenAPI/UI checks, source/binary manifest generation and `git diff --check`. Require zero skips for selected database/process cases. Review receiver proof separately from sender acknowledgement.
- [ ] Update evidence/ledger only with actual recorded pass/fail and external gates. M7A-24 remains component-only until dependencies and SHIP-GATE close. Mark M7A-23 local deliver/verify evidence as satisfied where supported, with its existing release limitations unchanged. Record the current source manifests because this worktree contains inherited uncommitted source; HEAD alone is not evidence identity.
- [ ] Obtain independent Critical/P2 review across authority, payload secrecy, signing version, crash states, public claims and manifests. A passing local test does not authorize deployment, a commit, or release classification changes.

## Grouped selector and required evidence

The runtime harness must enumerate and require these named groups, and fail if any expected top-level test is absent. Exact test count is computed from the committed selector inventory, not guessed from log text.

```sh
/opt/homebrew/bin/go -C services/platform test -race -count=1 ./securityagent ./apiserver ./webhooksecret ./agentsec-api ./agentsec-worker ./migrations -run '^TestSecurityAgentWebhook(PayloadClosedCanonical|VersionedSecret|Transport|Planner|Processor|PublicAPI|Readiness|Composition)'
node deploy/production/security-agent-webhook-runtime.mjs --group all
node --test deploy/production/security-agent-webhook-runtime.test.mjs deploy/production/security-agent-webhook-rollout.test.mjs scripts/security-agent-webhook-mounted-browser.test.mjs scripts/production-combined-e2e.test.mjs
npm run openapi:lint
npm run openapi:check
npm run openapi:test
npm run ui-api:check
npm run build
git diff --check
```

The owned-container `all` selector is:

```text
^TestSecurityAgentWebhook(AuthorityPostgres|ApprovalPostgres|IdempotencyPostgres|LeasePostgres|ReleaseCyclePostgres|RestartPostgres|PublicAPI|BrowserProcess)$
```

It additionally runs existing `TestIntegrationWebhookPostgresFencesTenantReplayVersionAndCompletion`, `TestSecurityAgentExportNonExportRoutePostgres`, and the current export approval/planner/settlement route tests under their supported release versions, without changing expected selection or SQL pins. Add `TestSecurityAgentWebhookComposition` in Task 4's composition test file and `TestSecurityAgentWebhookBrowserProcess` in Task 5's process test file so selectors cannot silently match nothing. Run the exact `npm test -- ...` command from Task 4 again and retain the command and installed Vitest version in the manifest.

Required proof artifacts: source and binary SHA-256 manifests; installed migration checksum/fingerprint; exact commands and versions; zero-skip Go JSON; SQL registered-function/grant checks; real two-organization/session positives and refusals; exact receiver body/HMAC/delivery-ID/request-count proof; restart boundary timeline and process-exit receipts; browser screenshot/request trace; redaction scan; final grouped log; independent review response. Keep secrets and raw provider messages out of all artifacts. Failed proof stays retained and marked failed.

## External gates and handoff

External gates are actual deployment migration/readiness approval, scoped IAM and immutable signing-version provisioning, approved public CIDRs/egress/DNS/trusted TLS, receiver-side HMAC/dedup verification for any such claim, live identity/model canary, M7A-23 dependency closure, observability/on-call/retention approval and SHIP-GATE. Do not fabricate them with local fixtures. Lack of any gate blocks release, not truthful local deliver/verify evidence.

The safe execution order is 1 -> 2 -> 3 -> 4 -> 5. Shared files have one owner at a time; the explicit handoffs prevent concurrent migration, runtime and handler edits. Each packet ends with RED/GREEN evidence and a review gate. Choose inline execution with `superpowers:executing-plans`, or explicitly authorize independent packet agents before using subagent-driven execution. Neither option starts until the parent approves implementation.

## Plan self-review

The five packets cover every design section: contract and signing (1), saved scope/approval/immutable state (2), planner/dispatch/restart (3), public API/UI and redaction (4), deployment readiness/browser/evidence/ledgers (5). The shared interfaces are the same across packets. The plan introduces no automatic resend, receiver callback, raw evidence export, release58 mutation, or production-availability claim. All verification is planned, not reported as already passing.
