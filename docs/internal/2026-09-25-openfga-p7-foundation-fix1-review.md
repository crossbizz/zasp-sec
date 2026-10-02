# P7 foundation fix1: the two findings are closed

SPEC: PASS for F1/F2 and the workflow omission supplement. QUALITY: PASS for the same bounded change. I found no remaining Critical, Important or Minor issue in that scope.

This is not acceptance of full P7, the original foundation packet, all 160 operations, a combined migration profile, production enforcement or release. No merge or deployment approval follows from this report.

## What I reviewed

I read the fix1 instructions, report, original review, remediation, manifest, complete scoped diff, evidence matrix, affected frozen source and retained RED/mixed/final logs. The review follows the Superpowers SPEC/QUALITY and evidence-before-claims approach. No product file was edited, no test rerun, no service started and no additional reviewer dispatched. Only this report was written.

Packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-foundation-fix1/`. Below, `C/` means its frozen `candidate/services/platform/`; `B/` means its frozen `before/services/platform/`. Those are the source citations, not moving live files. The original packet supplies unchanged context.

The manifest identifies eight modified files, one new regression test and the unchanged workflow handler supplement. I independently verified all 19 non-null candidate/before source hashes, the manifest SHA-256 `4b304a5ffd15ffcaaa52056c8c3dfda768dd0eea1ce7db2b6a28ca9e0011cf49`, and scoped-diff SHA-256 `f69c898b9b0d70aa0340aa9e57d77930f1d80c6309f0337126aefc6ba663d129`. I also compared both 67-entry green1/final source snapshots directly: their sole difference is the new test file. These checks establish source identity; the code and behavioral records establish the bounded verdict.

## F1, including every original consumer

Original severity: Important. Resolved for SPEC and QUALITY.

`C/migrations/sql/0080_production_authorization_enforcement.up.sql:180` introduces a narrow signed-context predicate. It compares scope, primary permission, a fixed operation allowlist, credential kind and explicit actor when supplied. Missing or unsuitable claims are false; `require_read` raises `42501`. It consumes the existing authenticated context and does not evaluate product permissions independently of Check. The existing owner/revoke loop at line 253 also covers these helpers.

| Original affected boundary | Fix checked in frozen candidate |
| --- | --- |
| `audit_page` | `0080_authorization_parent_reads.sql:133` retains both current-browser checks and adds `listAuditEvents`/`view_audit`, browser credential and signed actor checks at both occurrences. Parent filtering remains before pagination. |
| `runtime_session_query_status`, `runtime_session_query_hydrate`, `runtime_sandbox_query_status`, `runtime_sandbox_query_hydrate` | `0080_authorization_session_search.sql:3` requires `listSessions`/`investigate_sessions`, browser and actor. All four clones are enumerated at line 21. Hydration calls its guarded status function and retains exact allowed-session filtering at line 48. |
| `receipt_page` | `0080_authorization_parent_reads.sql:172` requires `listWorkflowMutationReceipts`/`view`, browser credential and argument actor equal to the signed principal before querying receipts. Existing receipt-parent filtering remains. |
| `workflow_list`, `workflow_page` | Same file, lines 158 and 165: fixed policy/integration/security-agent kind-to-list-operation mapping and `view`, before reading records. Unknown kinds cannot satisfy the predicate. |
| `risk_page`, `high_path_count` | `0080_production_authorization_enforcement.up.sql:190` and line 204 require the matching finding/path list operation and `view`; the count requires `listAttackPaths`. Allowed-key filtering remains inside the query. |
| `inventory_page`, `global_search` | Same file, lines 211 and 221: exact inventory kind-to-list-operation mapping or `globalSearch`, with `view`, before source reads. |
| All seven raw risk SELECT policies | `0080_authorization_risk_isolation.sql:5` and line 16 cover findings, finding evidence, finding factors, attack paths, path nodes, path evidence and break options. The predicate requires a closed product-read operation, `view` and the exact native allowed key. |

SQL filenames in this table are all under `C/migrations/sql/`. The raw finding allowlist is `getHomeSummary/listFindings/getFinding/globalSearch`; the attack-path allowlist is `getHomeSummary/listAttackPaths/getAttackPath/getAttackPathBreakOptions`. These product reads deliberately permit their underlying product rows. An audit-only, compliance or mutation decision cannot borrow an identical resource key for that disclosure. Existing nonlogin authority/writer policies were not broadened.

The environment-status leak is also closed. `C/migrations/sql/0080_authorization_session_search.sql:44` returns exactly `{"visibility":"resource_only"}` before backlog collection when the signed environment-view capability is absent. It does not invent healthy status, zero counts or timestamps. `C/apiserver/runtime_session_search_repository.go:277` strictly validates that single-field marker for both initial status and hydration; public search metadata remains omitted. The environment-view path still uses the existing full-status decoder.

The new regression uses real registered API transactions and the installed fence with legitimate grants from the authorizer, not hand-edited signed proofs. `C/apiserver/authorization_native_read_contract_test.go:108` checks eleven cross-operation native refusals; line 141 checks all seven populated risk tables under an audit-only grant. Its receipt case at line 170 rejects a different actor with `42501` and permits an empty own-actor result. Restricted status checks cover both source43/source50 pairs. Positive cases exercise audit, inventory, global search, workflow list and path count. The count positive asserts a successful nonempty scalar response, not a detailed count oracle.

## F2: the real lists can assemble their responses

Original severity: Important. Resolved for SPEC and QUALITY.

`C/apiserver/authorization_statement.go:104` now admits only the two required auxiliary operations, `listControls` and `listEvidence`, for either public compliance list. It retains fixed statement arity, session digest, source pins and the later public-operation/scope/actor rules. `getEvidence` remains exclusive to `getComplianceEvidence` with an exact evidence selector.

The native clone agrees: `C/migrations/sql/0080_authorization_parent_reads.sql:146` binds those same two auxiliaries to those same two public lists, requires `view_compliance` and the signed browser actor, and preserves the detail selector. There is no general auxiliary-query escape hatch. The source CTE still applies `parent_allowed` before aggregation or pagination at line 150. Unchanged `B/apiserver/authorization_openfga.go:85`, line 112 and line 196 require the `view` + `view_audit` + `view_compliance` intersection on every allowed parent, with current revision agreement and the applicable PAT ceiling checks.

The mounted cases at `C/apiserver/authorization_native_read_contract_test.go:209` use the actual compliance handler and repository over the enforcing database. Both lists produce a nonempty first page and a cursor, accept continuation, and return HTTP 200 for an empty allowed-parent set. The empty-set assertion checks response status; it is not a separate proof of every field in that response. Together with the unchanged pre-pagination parent filter, these cases close the original 503 composition defect.

## The six lines missing from the original packet

The supplement correctly attributes `workflow_handler.go` to P7, not Temporal. Its pre-P7 hash is `7d363ae0c93990174b9acf6b122b9f4a14399c91b0e813d262bc7a61fad377ae`; the supplemented current hash is `73e292febc6749cd46d41a347bb3f2ccf384c6c4a5b29818dcb26a433e981331`. I inspected its six-line diff. At `C/apiserver/workflow_handler.go:77`, a request-local handler copy receives `authorizationCursorKey` and invokes the former handler body. The shared handler is not mutated.

This code is unchanged by fix1. It was absent from the original 126-source manifest and 63-file behavioral checkpoint; the later compile-only capture did not provide behavioral proof. The separate omission supplement fixes the attribution and evidence boundary without rewriting the original packet.

Now `C/apiserver/authorization_native_read_contract_test.go:240` exercises the wrapper with the actual workflow handler, repository, statement classifier and native database list. A same-revision continuation succeeds. Changing membership role, reconciling and obtaining a fresh decision causes the old cursor to receive a non-200 response. The test does not assert a specific error status and is not a full-router authentication test.

## The evidence is mixed, then focused

| Retained record | What it establishes |
| --- | --- |
| `evidence/foundation-fix1-red.log` | Expected package FAIL, 37.601s. Real audit/workflow/risk/session disclosure, foreign-actor receipt access and both compliance 503s reproduced. Inventory/search `22023` and the no-op revision mutation were fixture failures, not vulnerability proof. |
| `evidence/foundation-fix1-green1.log` | Aggregate FAIL, 121.042s. The sole failing case was the new inventory positive, rejected with `55000` for incomplete provenance. Native denials, compliance/cursor, installed home (38.12s), installed search (20.08s) and selected units passed within that failed command. Owned PostgreSQL processes joined normally. |
| `evidence/foundation-fix1-inventory-corrected.log` | Retained focused PASS, 61.622s; installed case 60.51s, exit 0, owned PostgreSQL 5113 joined normally. All selected native/compliance/cursor cases passed after the fixture correction. |

The final command was `go test ./apiserver -run '^TestP7AuthorizationPostgres$' -count=1 -v -timeout=3m`. I inspected its retained output; I did not execute it. The final checkpoint matches all 67 captured candidate sources. Green1 matches 66, differing only in `authorization_native_read_contract_test.go`; the corrected fixture supplies the snapshot, evidence and matching winning observation. No product SQL/Go changed between those checkpoints, and the source14 exactly-one-winning guard was not weakened. Home/search were not rerun for this fixture-only correction. I do not relabel green1 as a green command.

These are meaningful installed-SQL checks with controlled permission-specific Check responses. They are not live OpenFGA/OpenSearch, browser, deployed-key or full-production checks. The complete 127-source foundation was not run together by these selected commands.

## What this cannot accept

The parent reports a separate combined Temporal profile failing `80.ready` after 78 and 79. I have not diagnosed that failure here, and this base61+79+80 packet cannot clear it. Previously reviewed finding78/note changes and parallel profile work are outside this diff.

Unsupported operation families, credential lifecycle/PAT/identity/bootstrap/capabilities, hierarchy creation and data-controls seeding, export publication fences, worker task/effect/phase and compensation authority, full current production composition, performance, migration ownership/key rollout and live provider/UI acceptance remain open. The broader foundation and release still need those gates.

Accept these two fixes and the omission supplement as a bounded review checkpoint. Keep the combined-profile failure open.
