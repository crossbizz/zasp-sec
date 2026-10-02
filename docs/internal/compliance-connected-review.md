# Connected compliance review

Reviewer /root/compliance_connected_review independently matched all95final
manifest paths. Read-only: no suites, live services, downloads or mutations.

Strengths: frozen-byte replay, lease/receipt-bound completion, authorization
recheck before consumption, read-lease cleanup protection, scoped safe sources,
historical test versions and unchanged release55. Saved local browser covers
native downloads, restart/replay/tenant controls and6signed-in checkpoints.

## Important: discovery and admission disagree

`services/platform/migrations/sql/fragments/compliance_jobs.sql:344` orders tied
last_claimed_at by job creation before scope IDs; claim admission at175 orders
by scope IDs. With batch1, older B is repeatedly discovered while lexicographically
earlier A must be claimed first. Both never-claimed scopes start at -infinity;
no successful claim changes the order. Jobs stay pending until expiry.

Use identical scope ordering. Regress through registered SQL/processor discovery
and claim with reverse creation order, batch1 and more waiting scopes than batch.
Existing fairness tests directly claim the expected scope and miss this seam.

## Important: HIPAA cards lack evidence links

`SessionsComplianceView.tsx:44` requests unfiltered evidence, while
`compliance_http.go:293` assigns it to soc2_security. The view at136 joins exact
control IDs. HIPAA controls load, even as fresh, but have no evidence rows.

Load both frameworks' evidence or selected-framework evidence with independent
cursor state/cancellation. Add populated HIPAA mounted-client coverage and actual
browser selection/source-version detail. Existing missing-evidence HIPAA fixture
cannot detect this. Preserve all-framework behavior.

## Important: valid cursors exceed public contract

`compliance_http.go:384` base64url-encodes8fields including scope/source IDs.
A permitted128character policy ID yields559characters with PostgreSQL spacing,
or539compacted. `administration-decoders.ts:52` and OpenAPI Cursor at4404 cap512.
A nonfinal page ending there fails frontend decoding and the Promise.all load.

Align bounded SQL/HTTP/OpenAPI/client cursors or compact safely, retaining
scope/operation/filter binding. Test actual emitted maximum-ID cursors through
the frontend pager. SQL-only pagination and short invented cursors miss this.

## Verdict

Critical: none. New Minor: none. Spec not approved; local quality/integration
requires these three fixes together. Root independently checked the named seams.
Keep real-SDK checksum regression on upgrades. Hosted Linux, approved advisory,
deployed IAM/KMS/lifecycle/TLS, live-provider, scale and production acceptance
remain separate gates; local fixes cannot close them.
