# Go export setup, 2026-09-19

The public Go boundaries accept a connected, export-only draft. Registered HTTP execution is still waiting on the SQL owner's final pin and database run at this checkpoint.

Owner: `/root/public_export_go_api`. This packet edits only the four assigned handler/repository files and three new export-definition Go files. No migrations, pins, OpenAPI, UI, deployment files, ledger or audit edits. I did not stage, commit, push, deploy or start a database container.

## What changed

The create/update body requires exactly `create_evidence_export`, `verification_kind=export`, `max_steps=1`, an explicit bounded AI cost, no `existing_test`, and `enabled=false`. It preserves the existing definition bounds and exact environment check. Connected export readiness is checked only for export intent; an export worker outage doesn't block an unrelated draft.

The frozen SQL contract uses `zasp_sa_export_mutate_definition16`, `replay_definition9`, `activate14`, `set_control15`, `definition_value7`, `definition_detail7`, `definition_page8` and `controls6`, with compiled release58 pins. These names use numeric suffixes here to describe argument counts, not actual SQL function names. The replay wrapper is the SQL owner's approved all-family receipt dispatcher, so a deleted export can still return its original receipt without exposing a deleted definition through a normal read.

New optional identity-aware workflow readers pass the actor to the installed58 value/page readers. Activation detail and controls do the same. Retained resource classification sends delete and export-to-other update attempts through export authority; SQL repeats classification under its write lock. If the admission function is missing, a retained export read can classify the object but cannot authorize a predecessor activation or mutation.

Worker health gates new export create/update, enabling export activation and enabling the export action control. Reads, replay, delete, activation withdrawal to `validated` and control disable do not use worker health. Environment-control enable retains its existing all-action semantics. Static production readiness and composite templates are unchanged.

The controls decoder accepts the exact sorted eight-key shape only with installed export admission. An absent export control is disabled/version0; enabled/version0, duplicate and misordered export controls fail validation. Existing CSRF, fresh authentication, idempotency, CAS, scope and original receipt handling remain in the same public handlers.

## RED, then GREEN

The first native `TestSecurityAgentExportDefinitionBoundary` run exited1. Ready create failed with `repository operation rejected`; draft, validated, supervised and autonomous activation readbacks failed; eight controls failed validation; export control PUT returned400. Those are real body/handler/decoder paths with only the external repository/database boundary replaced.

`TestSecurityAgentExportDefinitionRepositoryRouting` then failed all12 cases, exposing predecessor SQL for create/update/delete/replay/activation/reads and rejecting export controls before SQL. It now checks the exact frozen query, argument count, caller position and compiled58 pins.

Later focused REDs caught four more breaks: unrelated drafts blocked by export outage, eight-key controls accepted without export admission, omitted export cost accepted, and valid supervised activation of an autonomous definition rejected. A final missing-admission RED caught retained export activation/delete falling into predecessor writes. Each has a passing focused check after its fix.

Fresh offline race batch, exit0:

```text
apiserver       7.731s
agentsec-api    2.531s
agentsec-worker 4.005s
```

That batch selected the audit's export boundary/capability/catalog/manual/runtime/worker tests plus the new repository/admission cases and affected existing-test/Attack Lab lifecycle routing/read/control cases. A later race rerun after the retained missing-admission correction passed `apiserver` in3.976s. All runs used `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache` and `/opt/homebrew/bin/go`, with exact test selectors excluding PostgreSQL tests. No selected test skipped.

The Linux/arm64, CGO-disabled apiserver test binary compiled offline at `/private/tmp/zasp-public-export-go-api.test`. That binary predates the final retained missing-admission correction, so the SQL owner must rebuild before the registered batch. `git diff --check` passed for the seven owned Go files.

## The registered HTTP test is written, not yet accepted

`TestSecurityAgentExportDefinitionHTTPPostgres` uses `runExportDefinitionFixture`, the registered API login, real composition router and real repositories. It starts with zero export definitions/history/controls/runs, then checks create/update/replay/CAS, eight-key controls, validation/activation/replay, update resetting activation, and two public manual runs. It calls the existing `assertManualExportConnected` checks for claim, planner reservation/settlement, plan, approval, dispatch and capture.

It also exercises outage reads and withdrawal, blocked fresh enabling/update, CSRF refusal, deleted-resource receipt replay and authority loss. The fixture controls connected worker health and supplies middleware identity; it does not prove browser login, deployed worker health, external model/storage behavior, download grants or native saved bytes.

SQL signatures are frozen. The final pin and registered HTTP result are still the SQL owner's handoff. Independent review remains with the controller after the feature batch freezes.

## Checkpoint bytes

```text
becb3210b9dbdc591852ea4b78c8730714036e613178bf5bb2ba020fa60b67a7  services/platform/apiserver/workflow_handler.go
de674ae7be5fc8b1f98b7bba635152574e454a8e627f7a652197b8b90cfc4dba  services/platform/apiserver/workflow_repository.go
77508a7403a4d7260cdf105ac4e883dfd6ee0b901fe4aae255c601de0aef8cb9  services/platform/apiserver/security_agent_repository.go
87ca00f761c47987deeb49d5137b7e627c92193bffd32a4470212ac418c77106  services/platform/apiserver/security_agent_handler.go
2928d080cb197edf2e2287c2b7a0658b1ecd4245b87f9ea692677ee5c9d95d3a  services/platform/apiserver/security_agent_export_definition.go
c06b1ce6571772de5ebbe71b98be048bdd0944c8ba967240590a03c9d33e597f  services/platform/apiserver/security_agent_export_definition_test.go
3a6b045a1b131d4f92460ede8e3dc6e8705d1bb0173d69be49c41431b10612f1  services/platform/apiserver/security_agent_export_definition_http_postgres_test.go
```

Run the registered HTTP test against the SQL owner's frozen release58 bytes before accepting public activation.

## First registered HTTP run

The SQL owner ran the registered HTTP case and reported a focused RED in13.96s: create, original create replay, update, eight controls, control enable/replay and validated-to-supervised activation/replay passed. Editing that active definition with `If-Match: "4"` returned409 at the reset-to-draft step.

I traced the Go path: it forwards expected version4 unchanged. Incoming export update does not replace that version with a retained read. The SQL wrapper calls a clone of `zasp_security_agent_mutate_definition`, whose cloned workflow mutation checks `zasp_workflow_records`; the activation clone advances the Security Agent definition. I sent this mirror-version mismatch to the SQL owner. The HTTP expectation remains4, and the SQL owner owns the correction and rerun. Evidence is in `database/public-activation-batch-1.log`.

Correction: the SQL owner identified an existing release53 guard that checks public definition CAS and then remaps the inherited workflow mirror version. Mirror divergence alone is not the established cause. The SQL owner is running an exact reset-at4 reproduction; the HTTP fixture now retains the failed query and original database error in failure output. That test-file edit supersedes its hash above.

The raw driver error resolved this: the HTTP fixture reused `testCorrelationID` for multiple distinct `updateSecurityAgent` operations and hit `zasp_workflow_audit_organization_id_correlation_id_operatio_key` (SQLSTATE23505). I changed the fixture to issue a fresh scoped ProductID correlation for each request, as middleware does. No product SQL or Go version change was needed for that failure.

After that correction, the focused native race cases passed in3.349s and `git diff --check` passed. Updated HTTP test SHA256: `99e763b3cb182f993b14196c8e92358850ef397660e06874a63f41652ea232f4`. The other six Go hashes above are unchanged.

## Connected checkpoint

The next registered HTTP run passed the public reset/re-activation, two manual starts, and the reused claim/planner/approval/dispatch/capture checks. It stopped at the outage PATCH: expected503, got400 (`database/public-activation-connected-1.log`,22.01s).

A focused native RED confirmed capability=false was falling into malformed-body validation. The handler now returns `ErrRepositoryUnavailable` for export intent whose connected readiness is false. This changes the assigned workflow handler and boundary-test hashes; the next checkpoint below will supersede them. The SQL owner is also correcting definition-reader authority from `manage_workflows` to the route's existing `view` permission, with unchanged function signatures.

The affected race rerun passed in3.383s. Current changed hashes:

```text
2be85b2d750a148eb917dd6fbb01f3d93667f453cc401863ff0cc92bb8fec1a4  services/platform/apiserver/workflow_handler.go
b55ff82e2177f67bdc02268bfbaba8f749a70c5e330446666c04c682e4db1286  services/platform/apiserver/security_agent_export_definition_test.go
99e763b3cb182f993b14196c8e92358850ef397660e06874a63f41652ea232f4  services/platform/apiserver/security_agent_export_definition_http_postgres_test.go
```

The other four Go hashes remain unchanged from the first checkpoint.

The controller clarified the error boundary: malformed export bodies remain400 even when workers are down. A focused RED caught the health check running too early. The export branch now validates its closed draft first, then checks connected readiness; valid unavailable drafts return503. The expanded affected race batch, including existing-test and Attack Lab lifecycle regressions, passed in4.309s. `git diff --check` passed.

Latest superseding hashes:

```text
a3f6db2761b87adc3ce267fecd57f494bf7df08f217d596901e6c141894f2f96  services/platform/apiserver/workflow_handler.go
f5fb59498cde18c44025fb0800743c6781159680359018b815260126d6a26a43  services/platform/apiserver/security_agent_export_definition_test.go
```

The final expanded offline race selector exited0 across `apiserver`, `agentsec-api` and `agentsec-worker` while the SQL candidate fingerprint was held at `2d6913cde2acf27f155ff4f5b52189d7c31a56180baacbd894125aafaa4ef6ad`. A separate affected workflow repository/body/CAS/delete race selection passed in2.030s. No Go file changed after this hash checkpoint.

The registered HTTP rerun then passed outage reads, update refusal and export control disable/enable refusal. It reached the definition-level withdrawal assertion and exposed the predecessor's one-way activation progression. The controller approved export-only supervised/autonomous-to-validated withdrawal as part of this packet. The SQL owner is adding that narrow private-clone transition and recalibrating; Go's HTTP expectation and routing stay unchanged. Registered acceptance is still pending that rerun.

## Current-authority denial correction

At frozen SQL fingerprint `83416842dd0d4b0f70e9709045ae4534eb54efaabb5b77f1429edbfc1eb0cc7d`, the registered HTTP run reached its final revoked-authority replay. SQL correctly raised `42501: export definition permission rejected`; Go returned503 instead of403. The raw failure is in `database/public-activation-final.log`.

Systematic debugging traced the error through `classifyPostgresError`, which joins unrecognized SQLSTATEs to `ErrRepositoryUnavailable`, then `discoveryProviderError`. Public definition reads, controls and activation also lacked explicit authorization-error rendering. Neither shared classifier was changed.

A focused native RED exercised the real PostgreSQL classifier, all eight dedicated repository statements and seven HTTP paths. All exact permission-denial cases failed as expected. The native run failed in2.942s. Principal readiness, function-privilege denial, release readiness, scope denial and matching message text with the wrong SQLSTATE remained503 in that same test.

The correction matches only the eight dedicated export definition statements, SQLSTATE42501 and the exact message `export definition permission rejected`. That case becomes `ErrRepositoryAuthorization`. Its HTTP envelope is403, `authorization_rejected`, `retryable:false`. Every other error is returned unchanged by the new mapper. Read/control/activation handlers render the explicit authorization sentinel and delegate all other errors to the existing HTTP mapper. Workflow mutation and replay use their existing authorization response.

The focused native test passed in2.940s after the correction. Expanded coverage also checks existing400 and409 responses and verifies that predecessor/manual statements cannot acquire the new mapping. The offline race batch passed with uncached tests: `apiserver`12.823s, `agentsec-api`2.125s and `agentsec-worker`2.837s. The selector includes export boundary/routing/admission/authority cases, manual-start classification, existing-test and Attack Lab lifecycle/control routes, catalog/readiness, export planning/dispatch and API/worker configuration. Commands used `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache` and `/opt/homebrew/bin/go`. `git diff --check` passed.

Frozen Go SHA256 values sent to the SQL owner for the HTTP-only rebuild and rerun:

```text
dce2fc3704f22ad4954e19d6fbf412e3654721e3df8e7776e523a049e9154f6c  services/platform/apiserver/workflow_handler.go
d06bf347e47d940345a9ea984805f32c360f54aa9be5239a79a1a08a9cd20108  services/platform/apiserver/workflow_repository.go
dd7a9e9ee691d87af58a8edb3d9b2b3f5b9c48a21403aa9a49f51e16014b695c  services/platform/apiserver/security_agent_repository.go
e9894bc1649652e26ea2cdf60a1e58705081af46735a2586ae0ebf0ffd3306a9  services/platform/apiserver/security_agent_handler.go
add3d6493bc8e01d6e0639db358db48929d871d645935159c0ff2d6d40ce4660  services/platform/apiserver/security_agent_export_definition.go
b9cb06175317281032c94e0d39cb95b6f00b0a8a6f92ccb0c68a2c36c3b4c973  services/platform/apiserver/security_agent_export_definition_test.go
99e763b3cb182f993b14196c8e92358850ef397660e06874a63f41652ea232f4  services/platform/apiserver/security_agent_export_definition_http_postgres_test.go
```

No SQL, pin, UI, deployment or ledger edits were made by this correction. No commit, push or deployment was attempted. These native results do not replace the registered HTTP rerun, independent review, browser acceptance or deployed-runtime acceptance.

The separate offline race selection for workflow repository scope/receipts/replay, HTTP CAS/delete/PAT behavior and manual-start error classification passed in3.269s. The SQL owner then verified all frozen Go hashes, rebuilt the Linux test binary and ran only `TestSecurityAgentExportDefinitionHTTPPostgres`. That registered run passed in21.49s with container exit0 and unchanged SQL fingerprint83416842. The retained log is `database/public-activation-http-final.log`; Linux binary SHA256 is `9bf101ff5703fd214de15a9f2551f9d27f5c3b9b2c46dcc2f60f6e063674e88e`. No Go source changed after the frozen checkpoint. The registered HTTP blocker is cleared; independent review and any browser/deployed-runtime acceptance remain separate gates.

## Bearer receipt fix round

Review found the registered lifecycle covered browser credentials but not ProductAPIToken CRUD. Go already sends an empty receipt ID for bearer mutations; the export SQL wrapper rejected that valid predecessor contract. The controller assigned SQL correction to the database owner and registered HTTP coverage to this owner. No production Go change was made.

The HTTP fixture now runs a bearer subtest before its browser lifecycle. It injects the authenticated bearer identity, omits browser CSRF/origin/expected-scope/fresh-auth headers, and uses the real composition router, repository and registered API database for create/update/delete. It checks immediate retries and original create/update retries after deletion, stable body/audit/ETag results, stale CAS409, public get/list, and403 for original-request retries or new create after membership revocation. Durable state must have zero browser receipt rows and exactly three idempotency and audit entries. The fixture restores membership and browser identity before the connected browser flow. Browser create/update/delete each require a valid receipt header and all three receipt rows; the existing CSRF refusal remains in place.

The test-only file is frozen at SHA256 `7d0fd3c4e7b931ddef35e4cc783f2e50bd53c6d4ba5615966c30b4560a773532` for `services/platform/apiserver/security_agent_export_definition_http_postgres_test.go`. The other six Go hashes remain at the preceding checkpoint. Compilation plus the native mapper-scope test passed in1.132s. The focused offline race run passed in11.052s with export boundary/routing/admission/error cases, manual start, existing-test routes, workflow repository tests, HTTP CAS/delete/PAT behavior and PAT-without-CSRF routing. `git diff --check` passed. Both commands used the local toolchain and offline dependency settings recorded above.

The database owner will run the new registered HTTP subtest and its separate receipt regression at original SQL83416842 to capture RED before changing the SQL receipt guard. Registered GREEN and the recalibrated pin are still pending at this checkpoint. This fixture does not test token issuance or authentication middleware; it begins at a verified middleware identity, as the browser fixture does.

I read the retained registered RED in `database/public-activation-receipt-red.log`: the HTTP case failed in5.63s, with bearer create400 instead of201 and provider error `export definition receipt rejected` (SQLSTATE22023). The separate repository receipt regression failed at the same SQL guard in4.81s. Both fixtures joined their owned PostgreSQL process cleanly. The database owner then changed only the receipt predicate to accept empty or canonical IDs and recalibrated the SQL fingerprint to `67a4e601a5597f67a35f3be50f4a47a0a602b3097b3a9e4838e6fc09dcee6b72`. The HTTP test bytes are unchanged from the RED run.

At that held pin, the expanded offline race selection passed across `apiserver`12.372s, `agentsec-api`3.684s and `agentsec-worker`3.082s. It includes the earlier export/planner/dispatch/catalog/lifecycle selection plus workflow repository and HTTP PAT/CSRF/CAS/delete cases. All seven Go hashes were rechecked: only the HTTP test differs from the preceding authority-denial checkpoint.

The registered HTTP run then passed in28.97s, including its new bearer subcase in6.18s; the separate registered receipt/repository group passed in11.06s. I read those PASS records and clean PostgreSQL joins in `database/public-activation-receipt-green.log`. SQL checksum is `78e98a4f8ed1532f431e1f9f14aaf59770bd963faa37a3bb20a2c06ec86b9c05`. The database owner is finishing the remaining affected SQL/manual groups in that same log. This owner changed only the HTTP test and this progress report during the receipt fix round, with no production Go, SQL, pin, UI, deployment or ledger edit and no commit/push.

The grouped registered run is now complete: eight top-level groups passed and all eight owned PostgreSQL processes joined cleanly; the database owner reported container exit0. The remaining results were lifecycle9.28s, authority6.86s, predecessors8.89s, release6.36s, manual admission7.46s and manual HTTP5.54s. I checked the completed log, including its final PASS. Pin and Go source hashes remain frozen for independent re-review.
