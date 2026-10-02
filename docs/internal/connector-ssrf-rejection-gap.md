# M8-41 rejection-audit evidence gap

Classification remains component-only. This source inspection does not prove
live egress protection or durable rejection auditing.

The original task requires an attempted Nango/proxy/provider URL override to
be blocked and audited. `cmd/agentsecctl/security_release.go` evaluates three
supplied booleans. Its `TestTenantIsolationAndSSRFGates` supplies all three as
true; this checks the evaluator, not a product request or audit persistence.

There is already a product request boundary for negative testing. The mounted
workflow handler accepts integration configuration maps on create/update.
`services/platform/integration/manifest.go`, `Catalog.ValidateSetup`, checks
the exact schema cardinality and required keys, plus provider-specific values.
An extra endpoint/proxy override key can be attempted through that existing
configuration input even though it is not an accepted schema field. No new
public URL-override capability is needed to exercise rejection.

In `services/platform/apiserver/workflow_handler.go`, `integrationBody` returns
`ErrRepositoryOperation` on setup-validation failure. `mutate` then returns an
error before `MutateWorkflow`; allocating an audit ID beforehand does not itself
persist an audit. This inspection does not establish that any separate
middleware supplies the required durable record. That must be traced and tested
before changing classification or adding a duplicate audit path.

Next bounded verification: issue an authenticated, correctly scoped,
CSRF-protected create/update request with an otherwise valid provider setup and
an arbitrary destination override. Observe stable rejection, zero provider
requests and zero integration mutations, then query the durable scoped audit
store. Check that rejected URL/credential data is absent from records and
responses. Keep unauthenticated/foreign-scope attempts from borrowing the
selected tenant's audit authority. If the durable record is absent, implement
that missing path using current authorization and safe fixed metadata.

No source implementation or tests were changed by this inspection. It is a
candidate security batch after the active compliance feature, not a substitute
for discovery/sync or the remaining original milestones.

## Additional source constraints for the next batch

The inspected `ProductSecurity`/`NewProductMiddleware` path carries authentication,
body bounds and correlation handling, but has no durable audit dependency.
The workflow repository interface reaches durable mutation only after
`buildMutation` succeeds. A full mounted regression still needs to confirm the
absence of a record across the complete composed path; this source trace alone
does not replace that test.

Do not implement a blanket ban on all configuration URLs. The existing
`generic-webhook` connector intentionally accepts `destination_url` and validates
it with its own destination/secret-reference checks. M8-41 concerns forbidden
Nango/proxy/provider authority overrides, not removal of supported customer
webhook configuration. Use an otherwise valid provider setup plus an extra
forbidden override key for the regression; retain positive configured-webhook
coverage and the current egress restrictions.

The rejection happens after canonical intent and replay lookup. Any new audit
path must define retry/idempotency behavior explicitly and store fixed safe
metadata, never the rejected configuration or canonical request body. Test
create and update separately: update reads the existing scoped integration before
validating setup. Preserve not-found/authorization behavior for foreign records.

## Current implementation investigation, 2026-09-18

Root rechecked the shipping worktree at HEAD
8733b16f8d939d38a8157dd2519e57fc6f630542 after the compliance compatibility
review closed. No connector implementation has changed yet.

An additional early exit matters: workflow_handler.go:329 invokes ReplayWorkflow
before integrationBody, and workflow_repository.go:455 rejects any canonical
intent containing fields matched by containsSensitiveWorkflowField (line618).
An override attempt with an additional credential/password/secret field can
therefore fail before setup validation. A rejection audit added only to the
ValidateSetup error branch would leave that case uncovered. Keep secret-field
protection; do not pass the rejected body to durable storage to recover auditing.

The existing zasp_admin_audit table (0007_production_administration.up.sql:116)
already supports rejected outcomes and scoped actor/target/fixed metadata.
Its public read projection maps rejected to denied. However release52 pins the
source table catalog and ACL, including authority SELECT/INSERT and no
UPDATE/DELETE. Reuse requires proving the registered API execution authority;
do not casually add table grants or alter historical migrations. A new exact
authorized entrypoint may require an additive release, to be decided from the
full authority trace rather than assumed from table shape.

Independent read-only HTTP/auth/replay and harness investigation is active as
/root/connector_rejection_diagnosis. Root owns the audit-schema trace. Next
decision is the complete authorized rejection boundary and retry semantics,
followed by a mounted real-database RED. This remains component-only and is
not proof of blocked-and-audited product behavior.

Independent diagnosis completed read-only; mounted RED dispatched to
/root/connector_rejection_red using connector-rejection-red-brief.md. No
production edits authorized in that RED phase. Report will be retained at
connector-rejection-20260918/red-report.md.

Diagnosis confirms composition.go:141,143 requires manage_workflows, with CSRF
enabled at281; middleware.go:108-120 authenticates and router.go:111-133 checks
credential kind, expected scope, Origin/CSRF and permission before the handler.
Current session/PAT authentication intersects current effective scope authority
(repository.go:52-53,203-207). Existing effective-scope SQL is release19:324,
API EXECUTE grant383, authority audit INSERT139. API must not gain direct audit
table writes. Compliance authorization cannot be reused: its permissions differ.

Design direction: one additive guarded integration-rejection SQL operation,
credential kind/digest plus server-derived identity and exact scope; current
credential/membership/manage_workflows and update-target checks after blocking
locks. Commit fixed safe metadata before returning rejection; unavailable audit
persistence returns a nondisclosing unavailable response. No rejected bodies,
URLs, credentials or canonical intent are persisted.

Ruling: one rejection record per authorized HTTP attempt, without workflow
idempotency or success receipt claims. This keeps corrected same-key requests
possible and avoids persisting hostile intent. Cost if wrong: repeated attempts
produce repeated audit events; rate limits and retention remain applicable.
Preserve successful replay/conflict precedence, and explicitly exercise hostile
reuse of a successful key. The mounted RED and eventual GREEN must prove the
actual branch, current authorization and durable record; this diagnosis alone
does not satisfy M8-41.

Architecture and acceptance are now recorded in
2026-09-18-connector-rejection-design.md. Root checked the route declarations:
create/update admit both BrowserSession and ProductAPIToken, so the eventual
guarded write must cover both credential proofs and token permission
intersection. The active first RED uses browser authentication; it does not
alone establish token behavior. Implementation planning must retain that second
credential boundary and actual audit-read visibility.

Correction from actual registered-role fixture: the earlier statement that API
has EXECUTE only was too broad. Release10's legacy_api block at
0010_production_discovery.up.sql:756-765 grants CRUD on preexisting zasp_* tables,
including admin audit; registration699-701 assigns the API role. Release52 saves
these existing ACLs. Fixture confirmed non-superuser/non-bypass API login with
audit INSERT. No grants were changed. The design now explicitly preserves this
fact and adds no direct privilege; guarded new-function tests cannot be cited
as proof of database-wide immutable audit authority. A setup-only failing
privilege assertion was retained as diagnostic, not accepted RED.

Mounted RED now confirms the product gap. In connector-rejection-20260918/
red-run-final.log, four auth/scope/CSRF/foreign-target controls pass; positive
GitHub and webhook creates return201. All ten authorized create/update override
cases return400invalid_request with unchanged product tables and no observed
connector/default-HTTP dispatch, but zero matching durable rejection audit.
The run and PostgreSQL cleanup joined. This is failure evidence, not acceptance.
Root dispatched the connected GREEN implementation under
2026-09-18-connector-rejection-plan.md. M8-41 remains component-only.
