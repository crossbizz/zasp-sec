# M7A-24 signed response webhook design

Date: 2026-09-19. Status: selected design, not implemented. Scope: the original M7A-24 deliver/verify card. Implementation requires a separate execution instruction.

## Outcome and boundary

Make `send_response_webhook` a real Security Agent action that hands a small, redacted summary of the current run's evidence to a saved Generic Webhook integration. An operator must approve the exact destination version, evidence selection, payload digest, and signing-key version. A durable delivery record survives API and worker restarts.

This is a signed handoff, not remote remediation. An acknowledgement proves only that the configured HTTPS endpoint returned an empty HTTP 204 response to a request signed by this sender. Receiver signature verification, deduplication, and business effects require receiver-side evidence. We do not claim exactly-once receiver effects.

No action-time URL, arbitrary payload, secret reference, signing version, headers, or retry override is accepted. Do not add a receiver callback, status lookup protocol, arbitrary response action chain, or reusable webhook execution platform in this packet.

## Source basis and present gaps

The original requirement is `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`, M7A-24. The deliver/verify/release split is in `docs/internal/launch-execution-20260919/tasks.md`; the authoritative availability row is in `docs/internal/implementation_production_availability_v1.5.tsv`. Both keep production gates separate from local component completion. The existing inventory is `docs/internal/2026-09-19-security-agent-webhook-source-audit.md`.

`services/platform/securityagent/builtin_actions.go` has typed metadata and an in-memory signer/backend. Its map-based replay and run-ID-prefix evidence check are not durable product authority. `RegisterResponseActions` is not wired into the public production webhook action path. `action_readiness.go` correctly marks this action component-only. The public catalog, API unions, and Security Agents UI do not implement it.

Release 35 provides useful production code in `apiserver/integration_webhook.go`, `apiserver/finding_ticket_webhook.go`, and `migrations/sql/0035_production_integration_webhook.up.sql`: saved tenant-scoped configuration, registered SQL, redacted completion, exact-body HMAC, HTTPS-only destinations, DNS/CIDR pinning, redirect refusal, and empty-204 acknowledgement. Its event is `integration.webhook.test`; its table must not become an agent-response table. `agentsec-api/connector_aws.go` currently reads `AWSCURRENT`, which cannot bind a later delivery to an approved immutable key version.

M7A-23 now has sufficient controlled local evidence for its narrow deliver/verify criteria: registered run/export flow, canonical `manual` plus `run_audit` sources, browser downloads, restart replay, storage refusal/corruption/grant/read-lease tests, and a corrected all-pass current-release broad regression. See `security-agent-export-20260919/browser-fixture-progress.md`, `restart/final-report.md`, and `storage-matrix/README.md`. This does not close its M7A-22/M7-40 dependencies, SHIP-GATE, live storage/deployment proof, multi-step authority, a true second-organization stored-export positive, or a cleanup-worker process-retry proof. M7A-24 may reuse proven source-membership logic, not borrow M7A-23's release status.

## Options and decision

| Option | Benefit | Cost or failure |
| --- | --- | --- |
| Wire the component action directly to Generic Webhook test delivery | Small change | Wrong event and authority; in-memory replay; no approved evidence/key-version binding. Rejected. |
| Add a durable agent-response delivery, reuse the pinned transport | Keeps run/approval ownership explicit; shares proven network boundary | New registered SQL, version-aware secret resolver, worker, public status. Selected. |
| Build a general outbox with receiver receipt/reconciliation protocol | Could support automated uncertain-send recovery | New receiver API and operational contract beyond M7A-24. Deferred. |

Automatic choices are limited to the original handoff scope. Unknown send outcomes stop for human inspection. There is no automatic resend after the send boundary, even if the destination claims to deduplicate.

## Saved destination and current authority

Keep destination configuration in the saved, same-organization/workspace/environment `generic-webhook` integration. Add optional `signing_secret_version` to its configuration. Existing integration-test deliveries retain their current behavior; response action readiness requires a valid immutable provider VersionId plus the existing secret reference and valid HTTPS destination. The operator configures these through the authorized integration API. Planner output never supplies them.

Bind a definition control `response_webhook_destination` to `{integration_id, integration_version}`. The binding contains no URL or secret. The version must exist in the definition's full tenant scope, be configured, and satisfy the response-ready requirements. Changes to integration configuration invalidate an old binding; do not silently follow the latest version. Definition edits and approval checks use existing role, optimistic-version, audit, and control-history rules. Reject foreign or inaccessible destinations without revealing their existence.

Use a new narrow version-aware secrets interface. Resolve only the secret name derived from the authorized private reference under `<webhook-prefix>/<organization_id>/<workspace_id>/<environment_id>/<reference-suffix>`, with the approved VersionId. Scope comes from the registered claim, never the model. This tenant-qualified namespace is mandatory for the response action; do not fall back to v35's unqualified secret namespace. Reject path traversal and validate canonical scope identifiers and the existing reference grammar before lookup. Require the returned provider version to match. Do not fall back to `AWSCURRENT`, a different version, or another secret. This feature accepts VersionIds matching `^[A-Za-z0-9-]{32,64}$`; reject all others before a provider call. Clear owned secret bytes on every exit, and do not persist raw keys or HMAC signatures. IAM and network configuration remain external release inputs.

## Typed action, evidence, and approval

The production planner parameter shape is closed: `{destination_id, evidence_selection}`. `destination_id` must equal the saved definition binding. `evidence_selection` is a nonempty array, maximum 8, of canonical `{source_kind, source_id, source_version, association_digest}` descriptors using the installed run-source contract. Initial supported kinds are `manual` and `run_audit`. Reject duplicates, unsorted input, unsupported kinds, prefix-only matches, foreign runs/tenants, stale versions, and changed associations. Sort order is `(source_kind, source_id, source_version, association_digest)` bytewise. Selection must exactly match repository-loaded eligible descriptors; a model-provided digest is not evidence authority.

Reuse the release-58 run-source membership rules without changing export planner semantics. A response action need not create a same-run export first: the current bounded one-step run cannot depend on a second action being completed. The payload carries safe provenance descriptors, not export bytes or download credentials. An action-specific immutable selection digest joins the existing input digest, plan hash, definition/control version, destination integration version, and signing version in the approval snapshot. Build and persist the payload before presenting approval; the eventual body is that same byte string.

The approval floor is always `operator`, including autonomous definitions and schedules. A low-risk planner label cannot lower it. Existing approval expiry, revocation, run cancellation, RBAC, budget, and kill-switch checks remain in force. Check authority at preparation, approval, claim, and immediately before dispatch. Destination/key changes require a new plan and approval. No secret-provider or HTTP call occurs on a rejected authorization path.

## Immutable payload and signing

Encode exactly this schema as compact UTF-8 JSON with stable field order, without a trailing newline:

```json
{"schema_version":1,"type":"security_agent.response","delivery_id":"pid_00000000-0000-4000-8000-000000000001","organization_id":"pid_00000000-0000-4000-8000-000000000002","workspace_id":"pid_00000000-0000-4000-8000-000000000003","environment_id":"pid_00000000-0000-4000-8000-000000000004","run_id":"pid_00000000-0000-4000-8000-000000000005","step_id":"pid_00000000-0000-4000-8000-000000000006","plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence":[{"source_kind":"manual","source_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","source_version":1,"association_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}
```

Use the actual existing canonical source-ID grammar for each source kind. The literal manual digest above is structurally valid test data, but it is not a substitute for registered source membership. Maximum body size is 16 KiB. No prompts, evidence content, names, model output, titles, secrets, destination URLs, provider errors, export grants, or signed URLs appear. Reject unexpected keys at every decode boundary. Persist the exact bytes and their SHA-256 digest in a private immutable record. Redaction is an allowlist of fields, not string replacement.

Reuse the production pinned HTTPS client with a new event-specific response-delivery method. Send `Content-Type: application/json`, `X-Zasp-Event: security_agent.response`, `X-Zasp-Delivery-ID`, `X-Zasp-Payload-Digest`, and `X-Zasp-Signature: sha256=<HMAC-SHA256 of exact persisted bytes>`. Keep HTTPS-only port 443, no userinfo/query/fragment, bounded public CIDRs, validation of every DNS answer, pinned connection IP, original-host TLS verification, TLS 1.2 minimum, no proxy, no redirects, and timeout at most 10 seconds. The dedicated worker owns a 30-second dispatch lease. Never change transport rules to accommodate a test receiver; inject a trusted test transport only in owned proof processes and report that boundary.

## Durable state and crash semantics

Add migration 59, after the existing release-58 checksum/fingerprint, if slot 59 remains unclaimed at execution. If another migration owns it, stop and rebase this additive migration; do not repin or overwrite an existing release. Preserve every release-58 SQL file and checksum. Add a private response-delivery table with forced RLS and no application table grants. Registered functions alone atomically accept-and-prepare, claim, begin dispatch, complete, expire, claim parent settlement, settle the parent, and read the redacted status.

Identity is unique on `(organization_id, workspace_id, environment_id, run_id, step_id, action_id)` where `action_id = send_response_webhook`. Store one generated delivery ID, immutable destination/version/config digest, key ref/version, exact payload/digest, selection digest, plan hash, approval binding, lease token/generation, state, attempt count, and audit/correlation IDs. Replays return that record and do not regenerate its payload or dedup identity. A unique scoped idempotency key maps to that same action; reusing a key for different inputs is a conflict. A separate key cannot create another delivery for the same action identity.

| State/boundary | Allowed transition and result |
| --- | --- |
| `prepared` | Immutable intent exists, not yet approved; no provider calls. |
| Approved `prepared` | Claim atomically produces `leased`; competing claims are busy. |
| `leased`, before dispatch marker | Resolve/validate the pinned secret and exact payload. A known pre-send transient failure may retry, at most 3 claims; permission/schema/key drift fails closed. An expired lease may be reclaimed with a new fencing token. |
| `leased` -> `dispatching` | Registered begin-dispatch rechecks current authority and commits before the HTTP request. Only the current unexpired token can cross this boundary. |
| `dispatching` -> `acknowledged` | Empty HTTP 204, exact digest/identity, current token; record observed acknowledgement and settle the action as handed off. |
| `dispatching` -> `failed` | Definitive non-204/protocol rejection. Do not automatically resend, including for 429/5xx. Response text is discarded. |
| `dispatching` -> `uncertain` | Timeout, connection failure with possible write, process death, or expired dispatch lease without a durable receipt. No automatic resend. |
| Terminal replay | Return persisted status; zero secret or HTTP calls. |
| Revocation/cancellation before dispatch | Refuse send and record `cancelled`; no provider I/O. |

If the process dies after the marker but before the first byte, recovery still chooses `uncertain`. This conservative false unknown is preferable to an unapproved duplicate send. If acknowledgement was committed but its SQL response was lost, a status read recovers `acknowledged`. If HTTP succeeded but durable acknowledgement did not commit, recovery is `uncertain`, never invented success. A late, previously fenced process cannot overwrite a newer generation or terminal status.

Revocation cannot undo a request already in flight. Preserve an observed acknowledgement for audit even if the run is cancelled concurrently, but never revive a cancelled run or report remediation. A private delivery receipt and the parent run outcome are separate facts. Finalization uses a short bounded context independent of the cancelled request, without granting further network-send authority. After lease expiry it cannot turn `uncertain` into success.

A receiver should deduplicate using the stable delivery ID and verify the HMAC. A local test receiver must prove both. Sender correctness does not depend on a receiver dedup claim because uncertain deliveries are not resent automatically. Operators inspect uncertain handoffs out of band; this packet adds no resend button.

## API, worker, UI, and readiness

Preparation and the accepted planner candidate are committed by one action-specific registered transaction. It writes the immutable delivery intent and the exact plan, step, approval snapshot, payload, and digests together, or writes none of them. Approval uses the existing run approval endpoint, and execution uses the registered claim/dispatch/completion functions. Add a read-only `GET /api/v1/security-agents/{id}/runs/{run_id}/webhook-deliveries/{delivery_id}` under the existing authenticated tenant scope. It returns delivery ID, run/step IDs, destination integration ID/version, payload and selection digests, signing version, state, safe error code, acknowledgement time, and `receiver_verification: unproven`. It does not return destination URL, secret reference/value, raw payload, signature, provider body, or download capability. Foreign tenant and stale-session reads are refused before private data is loaded.

Compose a dedicated `security-agent-webhook` worker mode. Its role has only response claim/dispatch/complete/recovery functions and the current release-readiness query, with secret access limited to the configured webhook prefix and version-aware reads. It has no export-storage, policy-signing, parent-run settlement, or unrestricted owner SQL privileges. The normal Security Agent worker gets a separate bounded settlement claim and fenced settle authority. That path reads terminal delivery facts, preserves cancellation, and settles the parent step idempotently without secret or network access. Bound batches and lease recovery; no hot loop or unbounded retry queue.

Public action readiness is fail-closed unless the installed schema identity, active worker/readiness proof, saved destination binding, pinned-key configuration, and CIDR/TLS runtime contract match. Catalog eligibility does not mean a particular integration is currently authorized. Missing capability leaves the action disabled with a safe reason. Do not change the global ledger to production-available based on process composition alone.

Extend OpenAPI and generated unions, strict decoders, configuration controls, approval context, action details, and redacted delivery reads together. UI labels: `Awaiting approval`, `Queued`, `Sending`, `Handed off`, `Delivery failed`, `Delivery outcome unknown`, `Cancelled`. `Handed off` includes: "The endpoint acknowledged the signed request. Receiver verification and downstream effects are not proven." Unknown includes: "The request may have been received. No automatic resend was attempted." Never use `Remediated`, `Receiver verified`, or `Exactly once`.

## Verification and gates

The implementation plan assigns executable RED/GREEN packets for domain validation, registered PostgreSQL authority, versioned signing/transport, real worker/restart behavior, public API/UI, and controlled connected browser proof. Test two real organizations, two workspaces/environments, same-principal distinct sessions, changed destinations/keys/evidence, approval floor and drift, concurrent claims, conflicting idempotency, token expiry, cancellation, and direct-table-grant refusals. Negative authority cases must assert zero secret and HTTP calls, not only a returned error.

Restart proof must kill owned processes at prepared, claimed, secret-resolved, marker-committed, HTTP-ack-before-DB, DB-ack-before-client-response, and terminal-read boundaries. Correlate registered rows, run/step/approval identity, exact receiver bytes/signature and request count. Assert no resend after dispatch ambiguity and no new approval or model reservation after a settled replay. Retain logs, source manifests, migration identity, binaries, process-exit evidence, receiver transcript, and checksums. Never use fixture-shaped owner inserts as the source-membership or destination-authorization proof.

Local deliver/verify can close only with real product API/repository/worker paths and explicit controlled identity/model/secret/receiver boundaries. External release gates remain: authorized deployment migration and readiness, tenant-scoped IAM/secret provisioning and immutable version, approved public CIDRs and egress/DNS/TLS, actual receiver HMAC/dedup evidence if claimed, real identity/model canary, M7A-23 and its dependencies, observability/on-call/retention approval, and SHIP-GATE. Update the M7A-24 task and TSV evidence only after tests; keep component-only until those gates close. Do not relabel the existing v35 Generic Webhook browser proof as M7A-24 evidence.

## Design review result

All choices above stay inside signed, operator-approved handoff. The deliberate limits are metadata-only evidence, one action identity per run step, explicit key-version pinning, and no resend after an ambiguous send. The plan owns additive schema and narrowly shared transport wiring, preserves prior export/non-export route regressions, and does not assume local evidence is production release evidence.
