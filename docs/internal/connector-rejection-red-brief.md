# M8-41 mounted rejection-audit regression

This is the RED phase of the original connector SSRF task, not task completion.
Original acceptance: attempt Nango/proxy/provider URL override to an arbitrary
destination; the request must be blocked and audited. First reproduce the
missing durable audit using real mounted authentication and registered SQL
authority. No production implementation or migration edits in this phase.

Read connector-ssrf-rejection-gap.md. Build a focused PostgreSQL test through
NewProductMiddleware, NewComposition and the real workflow handler/repository.
Use actual browser session, CSRF, exact scope and manage_workflows permission.
Use the current compiled migrations and registered API role, not owner SQL for
product operations. Owner access is only fixture seeding and outcome inspection.
Existing compliance_http_postgres_test.go and compliance_exports_fix_postgres_test.go
provide patterns; do not alter compliance tests or weaken their assertions.

Use otherwise valid enabled connector setup with extra nango/proxy/provider
authority override fields. Cover create and existing same-scope update. Include
an override with a secret-like field to exercise the early replay filter. Assert
stable rejection, no integration/connection mutation, no provider dispatch and
one durable safe scoped rejection audit for each authorized attempt. Do not
require a new action name before design: match scoped actor, rejected outcome,
safe correlation and absence of hostile values. Derive fixture expectations
independently. Explain which provider transport is actually observed and which
zero-egress fact is only structurally guaranteed by this local path.

Keep foreign-scope/unauthenticated/CSRF failure controls distinct from authorized
rejection auditing. Do not let bad test setup produce the expected RED. Establish
valid authentication/route and a safe positive setup control before interpreting
an absent audit. Preserve generic-webhook destination_url support.

Observe and retain the expected failing assertion before any product fix. Report
setup failures separately, with exact commands/output. This phase may leave its
focused new test RED, which must not be committed or published. Root will use the
result to finalize the guarded durable-write design and continue GREEN.

Use apply_patch. Capture fresh BEFORE/AFTER identities and a narrow patch for
your files only; inherited changes belong to the user. Store evidence under
docs/internal/connector-rejection-20260918/ and a report there named red-report.md.
No edits to root ledgers. No staging, commit, push, subagents, host PostgreSQL,
network calls, advisory requests, dependency downloads or image pulls/builds.
Use existing cached owned isolated Docker PostgreSQL only, --pull=never; reuse
the existing compiled-test harness patterns. Do not touch voxeval containers.
Go /opt/homebrew/bin/go, GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off;
GOCACHE=/private/tmp/zasp-budget-go-cache. Join every process and owned cleanup.
Enumerate the focused test before running it; never run the entire SQL suite.
