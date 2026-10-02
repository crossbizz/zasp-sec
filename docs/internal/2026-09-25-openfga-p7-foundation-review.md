# P7 foundation needs two corrections

SPEC: CHANGES REQUIRED. QUALITY: CHANGES REQUIRED.

I found two Important issues in the frozen human/API foundation. No Critical or Minor finding is reported. This review does not accept P7, release the product, or change any of the original 728 requirements. The two findings concern implemented boundaries; the unfinished worker and operation gates don't excuse them.

Reviewed on September 25, 2026 UTC. The controller requested the Superpowers independent SPEC/QUALITY review and supplied its bounded review contract. I used that split, inspected the frozen source and retained evidence, and did not dispatch another reviewer, run tests, start services, or change product code. This report is my only write.

## The frozen bytes

All `C/` references below mean:

`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/`

`P/` is that packet's parent directory, `p7-foundation-review/`. Source line numbers refer to its candidate, not later live edits.

I recomputed these packet identifiers:

| Artifact | SHA-256 |
| --- | --- |
| `manifest.json` | `c6e940a8eeb6d4c89ad7fba5887f0ed427b878a7181e0c1e527311bd6b57d89a` |
| `baseline-to-candidate.diff` | `ba8687ff24b825e3773bfd080768fb893dcb84efa780bc9ed1b4ddf604b7da3c` |
| `hashes.sha256` | `e32188b7d536337a8818ec20e289da7ab5d56a2ef96dd50b34eacab958e28fbb` |

The manifest has 126 source entries, including 106 changed/new files and 20 context files. The controller's 319 source/baseline/live comparisons and 520 packet-hash checks are retained evidence, not behavioral coverage. I did not repeat those full mechanical checks. HEAD and the dirty baseline are identified separately in the manifest; this is not a clean-HEAD diff review.

I read the review instructions, full P7 report, approved design and P7 plans, operation ledger, organization identity policy, accepted P5/P6 review reports, all eleven contribution reports, the source-specific evidence matrix, the authorization implementation and SQL80 fragments, their caller changes and relevant tests. I checked the bounded HomeSummary UI/schema changes and CLI/vet deltas separately from the shared Temporal finding changes. Historical SQL9/43/52 was read only to trace the native functions used by the new policies and clones.

## Important F1: native reads treat allowed keys as permission-free capabilities

SPEC and QUALITY. The HMAC authenticates the decision, but several native consumers never check what that decision authorized. `allowed()` only matches scope, kind and native ID. It does not check the signed permission or operation. Those consumers have API EXECUTE grants or raw SELECT policies, so the Go statement classifier cannot protect a registered API connection that invokes them directly after a legitimate fence.

Primary locations:

- [Audit clone admission, line 132](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/migrations/sql/0080_authorization_parent_reads.sql:132). Both browser authorization calls become `checked_browser`, which checks current identity, credential, scope and CSRF at lines 110-116, but not `listAuditEvents` or `view_audit`. `parent_allowed` at line 96 only checks matching parent keys.
- [Session query admission, line 4](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/migrations/sql/0080_authorization_session_search.sql:4). Its helper inherits scope/actor checks, with no operation, permission or environment-view check. Lines 19-48 clone both status/hydration pairs using that helper.
- [Risk SELECT policies, line 24](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/migrations/sql/0080_authorization_risk_isolation.sql:24). Every API read policy uses the key-only predicate.
- [Receipt reader, line 166](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/migrations/sql/0080_authorization_parent_reads.sql:166). `p` selects the receipt owner without comparison to the signed principal. There is no operation or credential-kind check either.

Here are concrete source-derived reproductions. They were not executed during this review.

1. Give a current browser user `view` on a policy, but deny `view_audit`. Obtain the real `getHomeSummary` decision, whose `*` resolver includes that policy, then begin a transaction as the registered API login and call `fence` with the unchanged signed envelope. Call `audit_page` with that same user's scope, digest and CSRF and the compiled source52 pins. A public workflow-policy event for that policy passes `checked_browser` and `parent_allowed`, although no `view_audit` Check allowed it. A home decision with environment view gives the same route to receipt-bound sensor administration events. Nothing needs tampering.
2. A `getHomeSummary` decision with `view` on a runtime session can feed `runtime_session_query_hydrate` or `runtime_sandbox_query_hydrate` for that session. The native gate never requires `investigate_sessions` or `listSessions`. The query-status functions also return selected-environment backlog counts/timestamps for a valid proof with no environment-view capability, even an empty restricted collection. Go strips that status before its normal HTTP response; the API-callable SQL functions do not.
3. Obtain `listAuditEvents` with a direct `view_audit` grant on a finding and no `view` grant. The parent collection resolver includes findings, so this is a legitimate signed allowed key. After fencing it, raw SELECT on that finding and its evidence/factors passes the new RLS policy. `risk_page` also accepts it. An audit permission has become product-detail access. The same key-only pattern affects the other read families listed below.
4. Obtain a legitimate current `listWorkflowMutationReceipts` proof for user A with access to policy X. Call native `receipt_page(o,w,e,B,n)` where B has an unacknowledged, unexpired receipt for X in that scope. Its `r.principal_id=p` predicate selects B's receipt; `parent_allowed` accepts X. A's signed actor is never compared with B. Returned fields include B's idempotency key, intent and result. This is cross-user disclosure within a scope, not a claimed cross-tenant escape.

The complete affected consumer set identified in the frozen source is:

| Consumer | Missing binding |
| --- | --- |
| `audit_page` | Exact audit operation and `view_audit` |
| `runtime_session_query_status`, `runtime_sandbox_query_status` | Session-list operation/permission and separately authorized disclosure of environment metadata |
| `runtime_session_query_hydrate`, `runtime_sandbox_query_hydrate` | Session-list operation/permission; their inherited status payload has the same metadata issue |
| `receipt_page` | Signed actor, operation and credential contract |
| `workflow_list`, `workflow_page` | Operation/kind contract and read permission beyond allowed keys |
| `risk_page`, `high_path_count`, `inventory_page`, `global_search` | Their operation/read permission, independent of matching keys |
| All seven `authorization80_read` risk policies | Whether the signed permission permits product-row disclosure; inherited invoker risk detail readers share this exposure |

The four main read helpers are at `C/services/platform/migrations/sql/0080_production_authorization_enforcement.up.sql:178`, `:191`, `:195`, and `:204`. Workflow readers are at `C/services/platform/migrations/sql/0080_authorization_parent_reads.sql:158` and `:162`. The seven risk tables are findings, finding evidence, finding factors, attack paths, path nodes, path evidence and break options.

This isn't a forged-proof finding, and I found no HTTP path that bypasses the closed Go classifier for these arbitrary calls. It is a failure of the SQL-role boundary that this foundation explicitly added and tests directly. The recent native list-to-detail session fix establishes the same requirement. Sensor, recovery, data-controls, home, hierarchy and the normal session detail/event clones already contain stronger operation-specific native checks.

Fix the consumers' native contracts, keeping legitimate auxiliary reads explicit. A signed parent key must not silently authorize another permission, another actor's receipt, or scope-wide metadata. For retained raw risk SELECT access, define which signed read decisions permit those rows. Add one grouped real registered-API test covering the four cases above, with legitimate current signed grants; don't mutate a grant to manufacture the negative case.

## Important F2: the compliance list composition contradicts the classifier

SPEC and QUALITY. Both public list handlers issue a second kind of compliance read under the first operation's unchanged proof, while both the new Go classifier and SQL clone demand a one-to-one operation match.

[The classifier at line 105](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/apiserver/authorization_statement.go:105) admits only `listControls` under `listComplianceControls`, and only `listEvidence` under `listComplianceEvidence`. The native clone repeats that rule at `C/services/platform/migrations/sql/0080_authorization_parent_reads.sql:146`.

But [the HTTP control list at line 278](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/apiserver/compliance_http.go:278) calls `ListEvidence` for every returned control. And [the evidence list at line 301](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/apiserver/compliance_http.go:301) always calls `ListControls`, even when its evidence page is empty.

Reproduction from the source: mount the actual compliance handler with current authorization enabled and a valid current three-permission grant. Request `/api/v1/compliance/controls` with at least one returned control, or `/api/v1/compliance/evidence`. The first repository read can succeed; the second reaches `authorizationStatementAllowed` with the opposite internal operation and returns `ErrAuthorizationDenied` before SQL. The handler cannot return its successful page. Relaxing only the Go check won't fix it because the SQL check will still reject the auxiliary operation.

Existing evidence doesn't contradict this. `TestP7AuthorizationPostgres` exercises repository evidence list/detail, not the complete list-handler composition. `TestP7ComplianceCursorBindsCurrentAuthorization` uses `p7ComplianceCursorDatabase`, whose [line 112](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-review/candidate/services/platform/apiserver/authorization_cursor_test.go:112) returns canned data for the control read and bypasses the real statement classifier and SQL gate. It proves cursor behavior only.

Make each public list operation's required evidence/control assembly an explicit checked contract at both layers, with its existing permission intersection and allowed-parent restriction. Verify both actual mounted list paths through the enforcing database, including empty results and continuation. This is a deterministic caller/contract mismatch found by inspection, not a new failed test run.

## What held up in this inspection

The application decision path uses the official pinned Check adapter, current revision reads before/after Check, the original PAT ceiling and complete candidate enumeration. It signs copied route selectors and workspace selection after the final revision read. Empty collections don't become unrestricted queries. No old permission-array union appears in that enforcing path.

The attestation envelope authenticates exact bytes with a purpose-derived key. SQL rejects duplicate/malformed/expired envelopes before consuming their claims; private verifier storage and registration are distinct from API authority. Transaction context seals bind the session user and transaction ID, and context expiry is checked again. Current SQL fences lock revision, active membership, credential and target versions; the adapter returns conflicts without a hidden stale retry. F1 is downstream of those checks.

Pre-limit key predicates are present in the reviewed risk, inventory, hierarchy, policy, sensor and session queries. Session search puts its restriction before index aggregation and checks returned IDs before fenced SQL hydration. Native SourceID handling preserves console session/policy keys. The mounted session 404 behavior has specific retained installed evidence.

Data-controls uses forced RLS and only two checked migration-owner wrappers, with the API unable to assume that owner. Its installed evidence includes real non-superuser owner execution. Sensor mutations keep their native receipts and add receipt-bound audit facts; recovery preserves native enqueue/audit/outbox behavior. The organization model adds only the two human identity-admin relations, with no descendant resource inheritance.

Home's schema, generated type, decoder and component agree on the required paired-null status. The UI doesn't turn unavailable health into a healthy/degraded verdict. Verifier CLI registration, timestamp omission for unknown targeted pending age, and the two-file vet repair have bounded evidence. None of these observations accepts F1 or F2.

## Evidence is narrower than the source set

I reused retained logs. No unchanged test group was rerun.

`native-read-selector-green2.log` ends with exit 0 and PASS 34.163s: enforcement 15.86s plus session 17.25s, including native operation/selector negatives and mounted 404. Its matrix matches 63 captured candidate files, not all 126. The installed data-controls group ends PASS 15.954s, hierarchy/session group PASS 21.806s, and risk-attestation group PASS 20.454s. Their source-specific capture differences remain recorded in `evidence-checkpoint-matrix.json`.

The mixed `attestation-api-regressions.log` ends FAIL, exit 1. Its official-FGA/recovery/sensor/search positives are not an aggregate green run. The later session evidence corrects the signed-proof fixture expectation, but it doesn't retroactively change that command's status. Earlier production/live-FGA positives predate later classifier changes. That matters for F2.

The immutable sibling `p7-foundation-compile/compile.log` records API/worker/migrate compilation with `-run '^$'`, exit 0, times 1.056s/1.601s/0.559s and `source_drift=[]`. No tests were selected. It is compile-only evidence, including the worker package, not worker authorization proof.

The contribution logs retain their own narrower identities: model checks 1.205s, executable reconciliation 5.653s, verifier command/installed groups 3.256s and 16.706s, and the home integrated build exit 0. I did not convert those local component results into deployed-service or live-browser acceptance.

## Still cannot verify

The known incomplete credential lifecycle, PAT/identity management, bootstrap/capabilities, scope switching, unsupported operation families, hierarchy creates and data-controls seeding stay open. Export capture/publication/post-artifact fences and historical parent parity are not complete. Neither is the worker's service/task/effect/phase contract or retained compensation integration.

The combined Temporal profile stops at the recorded source72 mismatch before 78/79/80. Base API80's canonical61+79 readiness doesn't prove that profile, and the native source14 projection compatibility check doesn't prove current worker construction. Production composition with the final classifier, lock/performance behavior, deployed migration-owner compatibility, real key registration/rotation and live UI/provider acceptance remain unverified.

The original owner confirmed through the controller that `services/platform/apiserver/workflow_handler.go` has an omitted P7 change: six added lines create a request-local handler copy, bind `authorizationCursorKey`, and dispatch to `serveAuthorizedHTTP`. Its reported baseline SHA-256 is `7d363ae0c93990174b9acf6b122b9f4a14399c91b0e813d262bc7a61fad377ae`; current SHA-256 is `73e292febc6749cd46d41a347bb3f2ccf384c6c4a5b29818dcb26a433e981331`. The post-seal compile supplement captures that current hash; the original 126-source manifest and latest 63-file test capture do not. I treat it as omitted caller context, not frozen source attribution or a cursor-defect finding. The owner will provide a separate remediation supplement without editing this packet retroactively.

Keep the foundation unaccepted until F1 and F2 are corrected and their affected, source-pinned boundary checks pass.
