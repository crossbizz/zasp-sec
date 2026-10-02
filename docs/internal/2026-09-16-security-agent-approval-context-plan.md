# Persisted Approval Context Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline with the user's feature-batched testing and autonomous execution authorization. Independent review is required at the feature boundary.

**Goal:** Complete original M7A-88/89 approval context and reason/risk display through scoped product APIs without changing decision authority.

**Architecture:** Registered54 SQL projects one approval-bound step plus requester and redacted rationale inputs. Go validates and negotiates the optional context; generated contracts and strict client decoders feed explicit list/detail fields.

**Tech Stack:** PostgreSQL18, Go1.25.6, OpenAPI, TypeScript/React, Vitest, owned browser harness.

**Spec:** `docs/internal/2026-09-16-security-agent-approval-context-design.md`

## Global constraints

- Schema53 remains unchanged.54 must still be unpublished before editing its candidate.
- Exact single `X-Zasp-Approval-Context: v1` opt-in; unchanged decision receipts.
- Full organization/workspace/environment/run/plan/step binding, no evidence-ID target inference.
- Requester product IDs only; other text withheld. AI rationale never authorizes actions.
- Go tests use offline cache; database/browser tests run serially on this host.
- Focused behavior RED/GREEN, then one affected feature batch and independent review.
- Keep external advisory/publication/live-provider gates honest; no push while release gate fails.

## 1. Bounded authority and repository

Prerequisite implemented: public list response validation. REDd4e64c precedes
grouped race9f8c30 (1.858s) for item validity, duplicate IDs, state/run filters,
page bound and positive/incomplete cursors. Independent review found no blocking
issue. Add timestamp-only/invalid/empty-with-cursor negatives with this batch.
The pure Go context validator is implemented and reviewed without blocking source
findings; grouped racea3807b/d1357e passes. Malformed rationale follow-up also
passes racea6df72 (1.862s). SQL detail/page projections now exist and pass real
API-role PostgreSQL checks56f724 (5.856s), including four actions/two tenants,
exact action/target values, cursor traversal, withheld requester, foreign scope,
altered approval hash and authorization mismatch refusal. The hash refusal is
P0002 from the existing v24 strict plan lookup, not the new projection's55000;
302001 exposed an incorrect test expectation, not a successful unsafe read.
Repository/HTTP integration is now implemented: behavioral repository REDe97aff,
HTTP RED9e7da3, grouped Go race GREEN59ca19 and review-follow-up76ecf5 (2.053s).
Verified capability selects full-scope SQL with no fallback on probe error;
strict detail/page envelopes are validated before exact-header opt-out. Page
stripping copies items. Independent review found no Critical/Important issue;
its stale-map test weakness is repaired, with corrupt-page and list-probe refusal
coverage added. Real registered repository acceptance now passes groupedf1274f
(7.392s): actual constructors/release probe/API-role reads for four actions in
two tenants, unfiltered two-page traversal, and controlled capability-absent/false
legacy routing. RED7566a3 found empty optional strings incorrectly passed into
SQL; restoring legacy NULLIF normalization gives GREENc7a038 and expandedf1274f.
Follow-up review found no blocking issue. Minor exact equality between traversed
and filtered-page ID sets remains a test strengthening opportunity.
OpenAPI/generated types, strict client context decoding and list/detail v1 header
opt-in are implemented. Decoder RED239ca8 and transport RED624d77 precede grouped
GREENab7045 (136 tests and typecheck); OpenAPI39/39 and scoped lint pass244487.
Independent review found no Critical/Important issue. An explicitly present
undefined context is treated as omission by the decoder, a non-JSON-only minor
strictness gap. Server-side sanitization remains the redaction authority.
UI list/detail rendering is implemented in ApprovalContext.tsx and both approval
lists/drawer. RED56d172 precedes grouped107-test/lint GREENcd7f56; typecheck1bcb50
passes before the two added missing/withheld tests. Production build7436ef passes
all five stages; compiled-import check06a0fc passes7 client/8 server chunks.
Text-only rationale is separate from the persisted reason/catalog risk; missing,
withheld and unknown target remain distinct. Decision mutation code is unchanged.
Independent UI review found no Critical/Important issue; row accessible
descriptions beyond the existing ID-only aria-label remain a minor follow-up.
Post-decision context refresh is now explicit and read-only for terminal approvals.
It compares all existing non-context receipt fields before substituting only
display context; failures leave the recorded decision unchanged and never retry
a mutation. Requests abort on drawer unmount/approval change. Behavioral RED4be829
precedes89 tests/typechecke12e5f and expanded91 tests/lint/buildf9d99a; compiled
imports pass a8d2fa. Row aria-describedby now exposes visible context to assistive
technology, closing the prior review note. Independent follow-up review found
no Critical/Important issue. Deferred close/switch response coverage remains a
minor follow-up; mounted cancellation receipts are supplied, not SQL execution.
Actual owned browser acceptance now passes terminalbc9a0c (assertions59194c):
registered54/API-role projection through the built UI with an owner-seeded
temporary-policy approval. Pending/available and rejected/withheld requester
fixtures pass target/action/requester/rationale-absence checks, accessible row
description, drawer reason/risk, unchanged scoped authority snapshots and no
product mutations during reads. Both1440x1000 screenshots were inspected at
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-run-context-browser-rSRzmL/approval-context-available.png`
and `approval-context-withheld.png` in the same directory. No browser console
errors; all owned resources joined. Affected harness testsb07a46 pass55 with2
explicit container opt-in skips. Independent harness review found no blocking
issue; explicit response-state/list-section categorization assertions remain a
minor strengthening. Mobile layout, approval rationale available/withheld in
the actual browser and real decision execution were open at that checkpoint.
Follow-up browser47aa21 now verifies all three rationale states and a375px
rejected/missing-rationale drawer. RED473689 exposed568px scroll width from the
plan hash; scoped text wrapping repairs it and new viewport/bounds/overflow
assertions pass. Build9c487c/imports370ec1 pass; all four new screenshots were
inspected (see release checkpoint). Review's Important viewport-oracle gap is
closed. Mobile pending controls/available rationale and real decision execution
remain open. Page performance
with repeated runs remains open. Compiled54 pin is now
`17b48f5b7e28dd239f5a9de27874da046e7c4823bce875dabd1048d4f2d85766`.
Grouped PostgreSQL projection/fingerprint/rollback checks6bf0f1 passed16.809s
before the test-only assertion extensions. No publication or live-provider proof.
Undefined-functioncc8870 is setup failure, not behavioral RED evidence.

Create `services/platform/apiserver/security_agent_approval_context.go` and
`security_agent_approval_context_test.go`; extend the existing54 projection
fragment, `security_agent_repository.go`, `security_agent_handler.go` and compiled
pin. Add `security_agent_approval_context_postgres_test.go`.

Interfaces: `decodeSecurityAgentApprovalContext(payload json.RawMessage,
approval SecurityAgentApproval) (*SecurityAgentApprovalContext,error)` consumes
the private selected-step context. `SecurityAgentApproval.Context` is a pointer
with JSON tag `approval_context,omitempty`. Errors return only
`ErrRepositoryUnavailable`, with no input bytes.

- [ ] Start with literal tests binding approval/run/step/plan and four action risk
  classes. A representative assertion is:
  ```go
  got, err := decodeSecurityAgentApprovalContext(raw, approval)
  if err != nil || got.Action != "isolate_session" || got.Risk.Class != "containment" {
      t.Fatal("bound session action context lost")
  }
  ```
  Mutate one identity/hash at a time and require the fixed unavailable error.
- [ ] Observe meaningful RED with `go test -C services/platform ./apiserver -run
  '^TestSecurityAgentApprovalContext' -count=1`; separate setup/compile failures
  from behavioral failures. Implement typed validation with existing strict JSON,
  product-ID, hash and rationale sanitizer helpers.
- [ ] Add SQL detail/page entry points named
  `zasp_production_security_agent_run_context_approval` and
  `zasp_production_security_agent_run_context_approval_page`. Start from the
  existing authorized v24 detail/page results, preserving page metadata. Resolve
  each item's stored approval row by all scope keys and approval ID, then call
  `zasp_security_agent_run_context_v54` for its run. Require:
  ```sql
  approval.plan_hash = decode(substring(run_context->'detail'->'plan'->>'plan_hash' from 8),'hex')
  ```
  Select exactly one step where displayed id equals approval.step_id and select
  only that step's allowlisted target, action and authorization. Emit a private
  `{detail,context}` envelope for Go; do not emit full run histories per item.
- [ ] Route verified schema54 reads to the new functions. Older schemas keep
  existing SQL. Validate each envelope before constructing a public approval.
  Enforce expected effect, reversibility and TTL consistency with the bound action.
- [ ] Exercise actual API-role list/detail for all four actions, same-looking
  tenant/environment IDs, altered approval plan hash and unsafe requester strings.
  Assert safe public context and no protected sentinel bytes. Verify page order
  and cursors unchanged. Recalibrate54, then run affected trust/rollback/retention
  checks once after the SQL batch is stable.

## 2. Negotiation, contract and UI

Modify `security_agent_handler.go`, `openapi/openapi.yaml`, generated
`apps/web/api/generated.ts`, `apps/web/api/decoders.ts`, and
`app/features/securityagents/SecurityAgentsView.tsx`. Add separate approval-context
decoder tests and a small `ApprovalContext.tsx` display component with mounted tests.

- [ ] Add handler tests for absent, repeated, unsupported and exact opt-in. For
  each list item and detail, assert:
  ```go
  _, present := body["approval_context"]
  if present != wantContext { t.Fatal("approval negotiation changed legacy shape") }
  ```
  Validation must precede stripping, including list items. Test actual middleware
  unauthorized list/detail refusal without repository access or returned items.
- [ ] Specify fixed OpenAPI context/requester/reason/risk schemas and regenerate.
  Add decoder negative cases for arbitrary text, unknown keys, inconsistent
  effect/action, bad IDs and absent legacy fields. Use the real decoder in tests:
  ```ts
  expect(() => decodeSecurityAgentApproval(malformed)).toThrow("schema mismatch");
  ```
- [ ] Send the opt-in on real list/detail GETs. Render action, agent ID, target,
  requester state/ID, run and expiry in both pending/history lists. In detail
  show persisted-step reason, catalog risk source and distinct redacted rationale
  alongside existing effect/evidence/TTL/reversibility and decision controls.
  Never use raw JSON or HTML injection. Missing context says unavailable.
- [ ] Preserve retained cancellation/approval/rejection semantics. After a
  successful receipt, a context refresh may enrich display but must not turn a
  committed decision into a retryable mutation. Cover lost response, stale auth,
  denied role and unsafe values with mounted tests. Assert literal visible labels:
  ```tsx
  expect(screen.getByText("Risk: containment (action catalog)")).toBeInTheDocument();
  expect(screen.queryByText("protected-requester-sentinel")).not.toBeInTheDocument();
  ```

## 3. Feature verification and authoritative evidence

Full-page characterizationabdd98 found repeated run projection at1.475–1.518s.
Page-local scoped reuse is now implemented with per-approval hash/step/auth checks
and private assembly ACL denial. Group30d04a passes projection, mixed-run parity,
compiled fingerprint and rollback in15.692s;100-row samplesfc94e5 are37.5–38.9ms.
Current54 pin is17f6f97d3c291ae1b8f53af9583a027a504c9a9ea90313e52ccd46eb09e19fbf.
Independent source review found no blocking issue. Current-pin browser573a84
passes the three approval rationale states and375px mobile display; four
screenshots inspected and all owned resources cleaned up. These supersede earlier
repeated-run performance and predecessor-pin notes above. Reference-load API p95,
distinct-large-run pages, actual decision execution and publication remain open.

- [ ] Run affected Go race/real PostgreSQL, client/UI, OpenAPI, typecheck and scoped
  lint in grouped commands. Do not repeat unchanged broad suites per field.
- [ ] Build UI and check compiled imports. Extend the owned browser harness for
  actual list/detail API reads, unavailable/withheld values, safe target/requester,
  and unchanged authority after reads. Inspect screenshots; label all seeded
  histories. Keep actual decision-execution acceptance separate from UI mocks.
- [ ] Request one independent SQL/API/UI/release review, repair blocking findings,
  and rerun affected checks. Update the status ledger and release checkpoint
  without production promotion based on local proof. Explicitly stage only
  verified scoped files and push only after required release gates pass.

Self-review: authority, negotiation, display, permission, compatibility and
publication requirements each map to one of the three tasks. Missing legacy
evidence stays unavailable; current definition values never overwrite history.
