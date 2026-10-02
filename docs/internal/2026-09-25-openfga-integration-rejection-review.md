# Checked integration rejection: independent review

SPEC: PASS for this bounded rejection batch. QUALITY: APPROVED.

Findings: 0 Critical, 0 Important, 0 Minor. This is not full P7 acceptance.

I reviewed the original-operation replay, internal update preparation and safe rejection append against the brief and proposal. I found no delivered-code defect requiring correction. Valid integration mutations and the other gates below remain open.

## What I reviewed

The authoritative packet is `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-integration-rejection/` in the `cached-runtime-ship-20260917` worktree. Source anchors below refer to its frozen `after/` files, not Git HEAD.

I read the review instructions, brief, proposal, full implementer report, corrected manifest, complete 1,366-line scoped diff and frozen surrounding code for the named risks. I independently verified all 85 manifest source/artifact/diff hashes, including the 12 live source matches. The manifest checksum is `2a7dedf544ebf31e725c869746abf9b3eec04c7e6698f9d19984ab4a36f52a2d`; the scoped diff checksum is `232b0ff2efd65006d28ac1f828b7719dc96bbc9746cb344f233ac16148f8abc4`.

No tests or services were started for this review. I changed only this report.

## Contract checks

Original proof stays attached. `workflow_repository.go:134` and `:509` select the two closed native reads under the original create/update grant. `authorization_statement.go:22` and `:69` constrain operation, arguments, actor, scope and target. There is no second public-view permission substitution. `connector_rejection_repository.go:36` checks the command against the private grant and its attestation; enforcing mode cannot fall through to the legacy permission-array path.

The SQL enforces the same boundary. `0080_authorization_integration_rejection.sql:14` binds the original operation, `manage_workflows`, credential kind and exact allowed target. Lines 22-48 check membership, credential identity, revocation, browser CSRF, PAT ceiling, target liveness and wall-clock expiry. These checks only deny. The dedicated fence at line 51 still calls the full authorization fence, retaining revision and target-version enforcement; its exception branch always raises.

Replay remains read-only at line 81. It uses the existing scoped advisory-lock identity and canonical JSONB digest, checks current authority after the wait, returns an existing matching response, and reports digest conflict without inserting an idempotency row. Update preparation at line 102 binds both the authoritative integration and workflow record and rechecks after its row locks. Missing/foreign target hiding and the distinction between deleted workflow and deleted authoritative target are covered by the mounted tests.

Only fixed audit metadata crosses the append boundary (`0080_authorization_integration_rejection.sql:117`). Submitted configuration, URLs and arbitrary metadata cannot become audit arguments. The checked Go transaction at `connector_rejection_transaction.go:89` requires READ COMMITTED, runs the dedicated fence before and after the fixed append, and commits only after both succeed. Deferred rollback covers returned errors and panics. SQL repeats post-insert checks, so a direct native caller cannot skip them by omitting the Go final fence. All four callable family entries reach the native isolation check at SQL line 9.

Error translation is narrow (`connector_rejection_transaction.go:132`, `connector_rejection.go:38`): exact credential, authorization and target failures retain their public classes; changed authorization is retryable conflict; unrelated database errors are unavailable. Successful audit preserves the original rejected response. It doesn't convert a rejected mutation into success.

Outside the diff, I checked the inherited full fence and identity locks in frozen main80, the sealed transaction-local context in `0080_authorization_attestation.sql:71`, `authorizationProofJSON` and the checked query transaction, plus driver error classification. This addressed forged-context, post-wait authority and error-loss risks. I compared the historical workflow replay lock/digest contract as well. These were narrow dependency checks, not a renewed foundation review.

## Evidence and its limits

The final raw log is `terminal/integration-rejection-final.log`, SHA256 `ea4552b4388830f9011754306429f250898dd472050580de64b13aeca8c81e5d`. Its command selects `TestP7IntegrationRejection`, `TestConnectorRejectionClassification` and `TestConnectorRejectionHTTPBoundary`, with `-count=1 -v -timeout=5m` and `ZASP_P7_MODEL_TEST=1`. Terminal result: PASS, package 52.139s, exit 0. The installed case took 51.01s; owned PostgreSQL PID 25594 shut down normally. No warnings appeared in the final log.

That group covers browser and PAT create/update rejection, safe audit content, rejected-key reuse, seeded successful-key conflict and identical replay, current credential/permission/revision failures, observed lock waits, cancellation, write-error/panic/pre-commit rollback, native proof/actor/digest/target/operation refusal, and REPEATABLE READ/SERIALIZABLE refusal on all four entries. It uses actual registered non-superuser API SQL authority and a task-owned OpenFGA store with official SDK checks. Credentials and request identity are controlled fixtures. Provider-call tripwire count stays zero; product-state snapshots remain unchanged.

I also read the first installed failure and isolation RED evidence. The first installed run's pending-revision fixture and skipped restoration contaminated later assertions; those later results are not acceptance evidence. The isolation RED reached the native entries and exposed their acceptance of unsupported isolation. The final frozen candidate covers the correction. Ordered snapshot comparison and fixture restoration changes don't relax the product contract.

Seeded successful replay records prove replay behavior only. They do not prove that a valid integration was created or updated. The injected commit failure occurs before actual commit, not after an ambiguous network loss; cancellation is covered, but a separate elapsed request-deadline case is not claimed.

## Still required

Valid integration create/update, provider setup and discovery remain unimplemented by this slice. Keep their mutation paths closed until their own checked contracts are delivered.

Raw admin-audit write protection is separate required work. This append endpoint does not isolate every writer of `zasp_admin_audit`.

The changed SQL80 source/checksum has not passed the composed Temporal-profile regression in this packet. Cross-family isolation of the shared fence also remains open: the new native isolation assertions cover this family's four entries only. Catalog/source enforcement is present in the reviewed code, but I do not claim a fresh catalog-drift suite from this run.

Full worker task/effect/phase authorization, deployed Stytch/provider behavior and production acceptance remain outside this local proof. Retain those release gates.
