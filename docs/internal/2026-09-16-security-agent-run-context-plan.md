# Security Agent run context implementation plan

> Use Superpowers executing-plans, focused TDD and independent review on the
> complete feature batch. Keep all existing recovered work intact.

Goal: complete original M7A-86 without substituting local fixtures for production
proof. Architecture: private scoped database envelope, server-side sanitization,
opt-in public projection, strict typed client and separate UI sections.
Stack: Go, PostgreSQL, OpenAPI, TypeScript, React.
Spec: [run context design](2026-09-16-security-agent-run-context-design.md).

## Constraints

Preserve53 identity and existing verification. New54 requires all release
consumers and rollback coverage. Never expose raw receipt text.500-byte input and
output bounds; missing rationale differs from withheld rationale. Keep tenant,
principal and plan binding, old-client shape and server-owned authorization.
No task availability promotion until complete acceptance and publication.

## 1. Private sanitization boundary

Create services/platform/apiserver/security_agent_rationale.go and its _test.go.
Interface: sanitizeSecurityAgentRationale(string) (string, bool), where false
always returns empty text. The private decoder later maps false to withheld.

- [x] Write literal table tests: ordinary prose preserved, email/SSN/provider
  tokens removed, credential assignments/authorization/URL values removed,
  malformed text/private keys/overflow withheld. No provider or database doubles.
  Removing any sanitizer branch must fail its corresponding case.
- [x] Run `go test -C services/platform ./apiserver -run '^TestSecurityAgentRationale'`
  and record RED before implementing behavior.
- [x] Implement bounded UTF-8/control validation and deterministic redaction.
  Guard output size after replacements; never log input. Reuse no free-form
  generation or external dependencies. Add adversarial cases before any repair.
- [x] Run the focused race group and record GREEN. This helper alone does not
  implement the API or satisfy M7A-86.

Evidence: compile-only missing symbol cccd1b was followed by behavior RED4903ca
against a fail-closed scaffold. Initial race GREEN9fe908. Adversarial additions
produced REDef0cef for credential names and malformed quoted/marker suffixes;
race GREEN5bafe6 (1.961s) verifies their repair. No dependency or network calls.
The helper is not yet wired into the repository and final feature review is open.

Expected contract examples:

The private-key example constructs only a synthetic header marker, without any key material.

```go
text, ok := sanitizeSecurityAgentRationale("Contact person@example.invalid")
// text == "Contact [REDACTED]", ok == true
text, ok = sanitizeSecurityAgentRationale("-----BEGIN " + "PRIVATE KEY-----")
// text == "", ok == false
```

## 2. Registered database projection and rollout

Candidate-only progress: private envelope decoder race214d92 and scoped SQL
fragment PostgreSQL RED60bedd/GREEN4dc553 cover receipt/plan binding, retries,
tenant collisions, mixed scopes, ambiguity and direct access denial. Existing
manual triggers are preserved. Independent scoped review found no blocking issue.
The fragment is installed over registered53 only in the fixture;54 registration,
release fingerprint, consumer rollout and actual Get routing are still open.
These results do not check off registered54 acceptance below.

Registered database follow-up now passes grouped race e22c7c (18.287s), after
runner RED882239 and fingerprint calibration844d53/cf3453. It covers runner up/down,
Version54, compiled identity stability, scoped reads, drift/rebaseline refusal and
exact53 rollback retaining one organization-admission row. Independent review
found no blocking issue. The broad checkboxes below remain open because CLI,
all-consumer rollout, public repository routing and expanded retention acceptance
are not yet implemented/verified. Existing53 source and compiled identity stay
unchanged. The old53 client-ready gate refuses54, not a blanket old-binary claim.

- [ ] Add54 migration/release metadata/runner/readiness and CLI, keeping old
  functions and53 constants untouched. Add a separate scoped detail function
  returning `{detail, context}` privately. Context contains typed trigger and
  matching accepted receipt summary only. Assert full scope/run/plan binding;
  ambiguity refuses. Preserve direct-table denial.
- [ ] Real PostgreSQL RED/GREEN for absent/matching/wrong-plan/rejected/ambiguous
  receipts, execution retry, other tenant/environment and unauthorized principal.
  Extend services/platform/apiserver/security_agent_repository_postgres_test.go
  through a new security_agent_run_context_postgres_test.go fixture at registered54.
- [ ] Extend every release consumer listed in the spec. Test fresh/warmed
  API/runtime ingest/planner/action/audit consumers, invalid identity rejection,
  exact53 rollback and unsupported old binary refusal. No readiness bypass.

Binding predicate required inside the authorized projection:

```sql
receipt.outcome = 'accepted'
AND receipt.response->>'run_id' = run_value
AND receipt.response->>'plan_hash' = detail.value->'plan'->>'plan_hash'
```

## 3. API, generated contract and UI

Execution ordering: implement this contract/UI slice before54 so its exact wire
shape is testable without modifying the frozen53 candidate. Repository envelope
wiring remains part of task2/3 and is not bypassed. No real context is returned
until that integration is complete.

- [x] Add private envelope decoding in security_agent_repository.go. Construct
  public run_context only after validated scope and sanitized summary. Keep raw
  fields out of public types and stable errors. Add repository behavior tests.
- [x] Add header negotiation and public types in security_agent_handler.go;
  update openapi/openapi.yaml and generate apps/web/api/generated.ts. Handler
  tests cover absent/duplicate/unknown/exact-v1 header with independent budget
  negotiation. Older servers may omit the optional field.
- [x] Update apps/web/api/decoders.ts and the actual Security Agents client to
  request v1 and strictly decode optional context. Reject mixed withheld/nonempty
  summaries, extra fields, bad trigger values and invalid UTF-8-equivalent data.
- [x] Update app/features/securityagents/SecurityAgentsView.tsx and its tests:
  Trigger, Evidence, AI rationale, Plan, Authorization and execution sections;
  AI explanation disclaimer; absent/withheld states; React text only. Assert
  unchanged step ordering and deterministic labels.

Component evidence: Go RED00534c and missing-plan RED442253, race GREENabdc88;
browser RED302c2a, GREENea664b113/113. New fixture type error53e3ac repaired with
required templates; UI32/325c9b78 and typecheck4463ef. OpenAPI39/399da4fa,
lint9de76c, generated checka0edb5. Independent grouped slice review found malformed
credential-URL suffix disclosure. Four literal regressions fail8e10a4; whole URL
token matching plus delimiter/trailing-colon refusal passes focused race6e9401.
Scoped re-review approves that repair; ordinary quoted URLs may be conservatively
withheld. Targeted lint90e441 passes. Checkboxes record implementation/testing
only, not M7A-86 completion or final database/browser acceptance.

Repository integration now passes real registered54 PostgreSQL/HTTP race2b8370
(31.949s), after missing-context RED4847a8 and distinct API-role grant RED9db119.
The grant required54 fingerprint1d65f1584a006c5c3706c1b9022dc583e25c2f2981eb6ebd038adf94c23ccf1c;
current-pin calibration/lifecycle are in the same group. Fresh/warmed API/ingest/
planner/action readiness, tamper/refusal and rollback are covered, not execution.
Production decorator forwarding was absent; review found it, RED561563 reproduced
it, and wrapper plus controlled mounted composition pass57cebe. Re-review approves
this repair. CLI/audit consumers and real mounted-browser acceptance stay open.

CLI/audit configuration follow-up: focused RED2c3634 -> race438562; actual built
CLI54 lane9eaf20 passes48.946s, including principal/configuration registration,
policy rotation, retry and exact53 rollback. Actual audit factory/stored-session
queued HTTP62f52e passes10.405s. Independent review approves the bounded slice.
Audit worker execution on54 and application-compiled54 trust enforcement across
audit API/worker adapters still require verification before checking off the
all-consumer rollout. Neither result proves live provider or browser acceptance.

Audit adapter follow-up in progress: focused RED562a65 demonstrated that warmed
API/executor/outbox adapters accepted a failed application54 trust capability.
Uncached pre-readiness checks now pass focused race71133e. Independent source
review found no new blocking issue beyond the known missing54 client-ready grants
for audit executor/outbox. Actual role grants, fingerprint recalibration, coherent
SQL/metadata rebaseline refusal and registered54 completed-worker acceptance must
pass before this slice is complete. Broader worker check9b3e1e failed at denied
loopback listen; permission-enabled rerun is separate. No production promotion.
Follow-up: affected worker regressionff8de6 and migrations package131e1c pass.
Missing audit-role54 grants reproducedb111ad; narrow readiness-function grants
and compiled fingerprint7df9718bea4f3866dcdb677b18ddfd30a1fe9e18c3ce23ac64a5af6010c058c7
pass actual registered groupdc2f20 (46.399s). The coherent database rebaseline
control succeeds for inherited SQL but fails application pins, with restored54
and53 rollback verified. Completed-worker observer capability forwarding repaired
after RED7f8db0, GREEN3f2009. Follow-up independent review finds no blocking issue;
actual completed-worker matrix51214 is pending. Direct worker-role database
capability checks are not the same as actual worker Ready/composition execution.
Completed-worker matrix51214 now passes555bc8 (race,102.109s), including actual
executor composition and authenticated paged HTTP on52/53/54 and24 provider fault
cases. Seeded wakeup/controlled SDK storage do not prove durable outbox54/live AWS.
Deployment54 configuration and mounted-browser acceptance still need rollout.
Deployment artifact follow-up: RED6a8a8a/071802 -> grouped local release-contract
GREENf030c0 (204/204). Both54 precision phases support audit on/off; default49,
intake selection, exact registration ordering and predecessor refusal remain.
Targeted lint55e753 passes; updated runbooks do not authorize a live apply.
Independent review pending. Mounted-browser and deployed acceptance remain open.
Review found stale staging latest53/future54 assertions; REDf80cf2 -> full staging
gate/preflight76425d7/7, lint0d032a. Positive54 selectors and negative55 cases now
match the artifact contract. Independent re-review closes the Important finding;
bounded deployment artifact integration is verified, not live rollout.

Expanded retention follow-up: grouped race e0d9cb passes12.553s for release drift
and new owner-seeded reservation retention through53->54->53. Six populated
tables retain every column: organization admissions, runs, run budgets, unknown
and known-zero provider reservations, steps and step reservations. Explicit
version checks and restored compiled53 readiness pass. Independent review found
no Critical/Important issue; the suggested version assertion is included.
This covers those retained tables, not provider execution, concurrent cutover or
every53 data family. Mounted-browser acceptance and full feature review stay open.

Mounted display follow-up now passes84a553: real registered54 API plus controlled
login and isolated Chrome render available/redacted, withheld and missing rationale.
Exact DOM trigger/evidence and single-step authorization labels match HTTP; drawer
animation completes before inspected screenshots. Separate stopped display run and
its trigger/receipt are owner-seeded using a UI-created simulation's steps and a
distinct content-hashed fixture plan. This is not live planner execution. Review
closed missing-value assertions and duplicate-plan-hash fixture findings. Broader
feature review/publication stay open; screenshot inspection also found unstyled
production navigation links, recorded in the release checkpoint as next UI work.

Negotiation oracle:

```text
no header / two values / v2 -> original response fields
one X-Zasp-Run-Context: v1 -> optional validated run_context
```

## 4. Frozen feature acceptance

September16 source-review checkpoint: complete feature review found no
Critical/Important issue. Multi-step RunDetail characterization passes33/33
b486a3 with scoped lint cbe924. The optional duplicate-JSON-key hardening note
remains open (current authority input is PostgreSQL jsonb). Follow-up grouped
review approves the UI characterization and the M7A-87 duplicate step-ID binding
prerequisite; focused Go race5d5ac0 passes. Final release/publication remains open,
so these grouped acceptance checkboxes are not all closed.

- [ ] Run grouped affected Go/TypeScript tests, OpenAPI generation checks and
  typecheck. Verify registered API to mounted browser visual separation.
- [ ] Independent review of the complete feature diff against M7A-86, including
  redaction, scopes, migration consumers and rollback; resolve important findings.
- [ ] Update authoritative ledger with exact evidence and unresolved external
  gates. Run required release checks and UI build before explicit-path staging
  and publication. Existing advisory-scan approval gate remains unresolved.

Do not run full release suites between these internal slices. Repeat only
affected tests until the feature is frozen; reuse unchanged earlier evidence
within its exact scope. This plan is unfinished until every checkbox is verified.
