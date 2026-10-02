# Manual-trigger provenance across agent execution

Required connected work for the original agent platform and M7A-23. This
design does not complete or reclassify a microtask. Routine choices follow the
user's autonomous-execution instruction; original scope remains unchanged.

## Evidence and problem

The accepted export collector represents manual source_id as the original
64-lowercase-hex intent digest. It checks trigger_id against trigger_digest,
the exact receipt version and full parent scope. The generic historical
zasp_security_agent_create_run path stores that digest as trigger_id.

Current Go SecurityAgentRun, SecurityAgentApproval, SecurityAgentRunClaim and
their TS/OpenAPI contracts require ProductIDs in legacy evidence fields.
SecurityAgentRunContext already discriminates trigger kind, including manual,
but validates every id as ProductID. Public RunSecurityAgent currently accepts
finding/session/attack_path inputs, not an arbitrary manual digest. A manual
fixture in the collector therefore does not establish a usable public manual
workflow. Do not change validProductID globally or claim this is only a UI gap.

## Chosen representation

Add optional manual_trigger to public run values, approval values and private
worker claims. Its exact closed JSON shape is:

```json
{
  "kind": "manual",
  "intent_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "version": 1
}
```

The digest is exactly sha256: plus64 lowercase hexadecimal characters. Version
is an integer1..9007199254740991. The outer run/approval/claim already supplies
the run identity. Registered SQL must bind this object to exactly one original
receipt through organization/workspace/environment/run/definition and its
original trigger_id/version/digest. Object shape alone is never provenance.

Do not place the digest in legacy ProductID arrays. For manual runs,
evidence_ids is an explicit empty array and manual_trigger is required.
For their approvals, evidence_summary is an explicit empty array and the same
manual_trigger is required. Nonmanual runs retain their current nonempty
ProductID arrays and must omit manual_trigger. Do not emit null, accept a mixed
manual-plus-ProductID representation, or silently remove invalid legacy IDs.

Run-detail's outer evidence_ids must equal run.evidence_ids. Its run_context
trigger remains the existing {kind,id,version} form: only kind=manual uses the
64-hex original intent id; every other kind continues to require ProductID.
For a manual run, this trigger must agree with manual_trigger's digest/version.
Every embedded approval must carry the same provenance as its parent. A manual
approval read independently needs the SQL receipt binding even without parent
detail in the response.

Worker claims retain original trigger_id. A digest trigger_id is accepted only
with a matching manual_trigger from the registered claim query. ProductID
claims must not carry manual_trigger. Planner context uses the exact same
manual id/version, and its canonical digest includes the typed provenance.
The model cannot supply or override provenance.

Planner wire agreement: the private canonical SQL context adds optional
`run.manual_trigger`, equal to the typed claim. Its manual `untrusted_evidence`
entry uses kind=manual, the raw64-hex intent ID, the same version and the existing
bounded untrusted-summary sentinel. Nonmanual contexts omit manual_trigger.
The Go processor copies this object into prepared model input as manual_trigger;
Prepare owns the copy. The SQL snapshot retains the original canonical context
and digest. This needs no additional snapshot columns.

## Authority and compatibility

Extend only additive release58 paths and their restore catalog. Preserve all
predecessor contracts and nonmanual behavior. Existing role exclusivity,
lease, membership, definition-version binding and source-read checks remain.
Manual requester authorization cannot borrow scheduled-definition actor rights.

Selection still comes from real persisted run associations. Manual intent does
not authorize an arbitrary finding, test, Attack Lab step or storage object.
Export may select its own valid manual receipt or linked run audit evidence;
other source references need their independent original same-run associations.

Do not reinterpret historical digest-style nonmanual receipts as ProductIDs or
manual intent. Their declared kind and retained source association must resolve
unambiguously; otherwise fail closed and record the unsupported retained case.

The public manual-start producer is a separate required part of this connected
flow. It must derive intent from a closed, authenticated request, persist the
receipt atomically with idempotency and audit, and return the bound provenance.
It must not accept a caller's digest as authority. Before defining its request
shape, reconcile the original product run-now contract and current definition
trigger rules. No new endpoint or broader action authorization is chosen here.

Original-plan reconciliation: M7A-70 (plan line4000) requires manual
POST /api/v1/security-agents/{id}/runs with an optional finding/path/session
trigger ref. The existing handler requires trigger_kind and a ProductID
trigger_id, so no-reference manual start is missing original scope. Extend the
same endpoint, not a parallel endpoint, when implementing the authenticated
intent producer.

Admission reconciliation now confirms the current registered existing-test
wrapper requires kind finding/attack_path/session, maps session to
runtime_decision, and delegates non-test actions to run_v24. Its private admit
requires the receipt kind to match the definition's scheduled trigger kind.
The export planner independently enforces the same equality. Merely making
the HTTP fields optional cannot make this workflow work. The historical
create_run function permits manual receipts, but lacks the complete current
public idempotency, permission, action-binding and budget admission contract;
it is not a safe public shortcut.

Chosen public contract: environment_id remains required; trigger_kind and
trigger_id must either both be absent or both be valid explicit source fields.
Reject null, empty, partial, duplicate and unknown fields. With both absent,
the API requests a server-derived manual intent; it does not accept a manual
digest, requester, scope override or receipt version from the caller. Explicit
source requests retain their existing matching and cross-scope checks.

A no-reference start is an operator invocation of the current activated
definition, not a rewrite of its automatic trigger configuration. Persist a
manual receipt while leaving that definition unchanged. Keep exact current
version, enabled activation, requesting principal permissions, immutable
definition provenance, action-specific prerequisites, concurrency and control
checks. The typed manual exception to scheduled-kind equality must not become
an exception to any of those authorization checks. If an action needs a source
that is absent, it cannot invent a target or reuse another run's evidence.

The SQL authority derives the version1 intent digest from canonical structured
data containing a manual-intent schema version, organization, workspace,
environment, requesting principal, definition ID/version and idempotency key.
Fresh server-generated run/audit/correlation/receipt IDs are excluded so a retry
can return the original transaction. The same transaction creates the run,
original trigger receipt, audit and scoped request receipt. Changed intent
under the same key conflicts; replay repeats current authority checks without
creating a second run or audit.

The SQL owner confirmed the future private signature zasp_sa_manual_run with13
arguments: organization, workspace, environment, definition, requesting
principal, idempotency key, expected version (bigint), server-generated run,
audit, correlation and receipt IDs, then exact release58 checksum/fingerprint.
The Go route checks the database's registered release58 capability and never
falls back to historical create_run. This capability alone does not prove
workflow activation or manual SQL exists. The SQL function must enforce its own
release, principal and admission checks. The helper and restore wiring are not
implemented yet; controlled Go response tests are component evidence only.

## Implementation boundaries

SQL owner: claim, run page/detail, approval detail/page/decision receipt and
context assembler projections; digest/receipt binding; fresh authorization;
additive restore/pin and actual registered regressions. Keep private provider
locators, source bytes and unsanitized rationale out of public objects.

Root: Go types/strict readers, run/approval/detail consistency, worker claim
and planner validators, OpenAPI discriminated contracts and generated types,
TS decoders and real run/approval UI display. Display manual intent digest and
version explicitly, never a ProductID link or a claim of security remediation.

## Acceptance that remains to be proved

- Registered public admission produces the real receipt; no owner-seeded run
  or plan substitutes for this workflow proof.
- Claim, planner context, reservation and acceptance retain the same full-scope
  manual provenance. A different tenant/run/definition/version/digest refuses.
- Nonmanual ProductID and absent optional field behavior stays unchanged.
- Missing/null/aliased/duplicate/unknown fields, zero/overflow versions, mixed
  arrays and mismatched detail/approval provenance fail before use.
- Authenticated mounted run and approval views render the actual manual run;
  source permission loss and requester membership loss refuse export.
- Worker interruption/retry cannot change provenance or duplicate admission.
- Original multi-step workflows remain required; typed manual provenance does
  not remove the current single-step execution restriction.

This is a contract design, not implementation, fixture acceptance or live proof.
