# Release58 browser lane: first connected run failed

2026-09-19, initial implementation packet. I changed only the assigned browser scripts, their tests, the new API process fixture and this report. No SQL, release pin, product UI, apiserver product, worker, store, deployment or ledger edits. That packet started no browser, container, provider or network service. No commit or push. The controller later ran the connected candidate; its failed result and follow-up are recorded below.

The implementation uses the TDD and verification-before-completion skills. I read the browser, storage/download and restart audits; the controlled local fixture stays separate from live-provider and deployed acceptance.

## Frozen interfaces

The browser owner coordinated these contracts with the worker and storage owners before consuming them:

- Mode: `ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT=true`. Any other present combined-mode flag is refused, including values such as `false`; the executable override `ZASP_COMBINED_E2E_CHROME` remains allowed. No broad-mode fallback.
- API process: `TestSecurityAgentExportBrowserAPIProcess`. Worker process is the other owner's `TestSecurityAgentExportBrowserWorkerProcess`.
- Shared environment uses `ZASP_SA_EXPORT_BROWSER_` plus `PG_PORT`, `WORKER_PORT`, `DEADLINE`, `OBJECT`. Each process also needs its exact `API=true` or `WORKER=true`; worker takes `DSN`. Deadline is at most 30 minutes away.
- `OBJECT` is a canonical owned directory ending in `/zasp-production-e2e-<random>/export-store`. The worker starts first, creates the store only when absent and opens it on restart. API only opens it. `Close` retains the directory; parent cleanup removes its owned root after joins.
- Store configuration: bucket `zasp-compliance-exports`, owner `123456789012`, KMS key `arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111`, package limit `8<<20`. API imports `internal/exportfixture` and uses its `ReadOnly:true` transport. Individual downloaded formats stay within4MiB.
- GET `/readyz` retains the original Host for the four fixed planner/action/compliance-writer/cleanup services. API rejects other hosts, methods, paths, query strings, credentials, fragments and unbounded requests before its underlying transport. Parent startup uses the worker's exact loopback aggregate readiness endpoint.
- POST `/plan`, `/dispatch`, `/capture`, `/settle` calls the worker owner's actual composed phase operations. No owner-written definition, run, plan or capture. The worker also has `/cleanup`; this shortest browser flow doesn't call it. `/settle` can claim ordinary queued work, so the browser fixture creates only one run.

The API process calls `buildRuntimeDependenciesWithReadinessTransport`, retaining real PostgreSQL pools, Stytch-shaped callback authentication, product sessions, authorization middleware and export retrieval. Only service placement and the external S3 transport are controlled. Production routes and classes are untouched.

## What the runner now asks the browser to prove

Selected startup uses the existing pinned, pull-never PostgreSQL container with the network-none relay. It upgrades to58, checks max release plus exact checksum/fingerprint and registers the two compliance logins through `agentsec-migrate register-compliance-workers`. Baseline counts require no definitions/history/runs/plans/approvals/export links/jobs, export action control or product session before login. Fixtures seed identity, scopes and required inventory scope cutover only.

Author, approver and foreign user each have their own Chrome profile and controlled OAuth callback. `startIdentityServer` keeps distinct member/session/JWT identities; no session-row insert, cookie injection or injected RequestIdentity. The foreign provider response maps to the separate foreign Organization. Callback/bootstrap principal and scope checks stay in the browser flow.

The author creates and updates an export-only draft with explicit budget1000000, enables environment/action controls, validates and enables supervised execution, then manually starts with empty legacy evidence IDs. The composed planner supplies the pending approval. A separately authenticated approver decides through the UI, and worker phases dispatch, capture/render/upload and settle the original run.

The run's existing ExportPanel supplies JSON, CSV and readable native downloads. The file oracle requires a matching GUID/start/completed event, exact filename and nonempty final file, and compares actual saved bytes with the persisted package member. It checks package hash/size separately from each format's hash/size, then checks scope/run/step, ordered selection and the original manual intent inside `content_json` against its digest. Completion must leave the parent in `needs_human`, not claim remediation.

API and worker restart after completion; a fourth native JSON download must match the original. Store object identity and one link/job must remain unchanged. The foreign callback-authenticated profile must receive a403/404 status refusal for the original export.

Eight successful public lifecycle mutations need original receipt/audit identities, expected scope, browser origin, CSRF and hashed idempotency-key evidence. Traces omit cookies, CSRF values, provider credentials, grant tokens and response bodies. The evidence directory retains screenshots, three original saved formats, restart JSON, source/binary hashes, actual ports/profile identities, redacted request trace and cleanup result. Evidence is outside the disposable root.

Every new process enters existing owned cleanup. The worker joins before PostgreSQL cleanup. Extra browser profiles close too. Failed joins retain the process root and errors; exact container identity cleanup remains with `owned-browser-postgres.mjs`. This is wired behavior, not an observed runtime cleanup result.

## RED was behavioral

The selected-mode test initially returned false for exact `SECURITY_AGENT_EXPORT=true`; it failed before any resource allocation. The first byte-oracle test exposed accepted mismatched bytes/missing native events. Release preparation still using57 failed against58 readback. The API readiness test showed a foreign host reaching its underlying controlled transport. Those four failures were recorded in this task's tool output before the respective fixes.

GREEN now covers mode isolation, stale pin refusal before registration, exact saved formats/completed GUIDs, callback identity separation and the readiness allowlist. Missing imports, skipped process entries and compilation failures weren't used as RED evidence.

## Fresh verification

All commands ran from the worktree with cached Node22.23.1 and offline Go settings. No selected test skipped.

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test scripts/security-agent-export-mounted-browser.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-name-pattern='export browser mode refuses|export callback|broad lifecycle orchestration|Security Agent simulation selection|combined API environment|failed checkpoint|combined PostgreSQL startup' scripts/production-combined-e2e.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/eslint/bin/eslint.js scripts/security-agent-export-mounted-browser.mjs scripts/security-agent-export-mounted-browser.test.mjs scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
```

Four export helper tests passed;16 combined tests including cleanup subcases passed. The latter execute real orchestration branches against controlled process boundaries, keeping compliance56, AttackLab57, simulation and broad-mode routing separate. ESLint exited0. Both modified script modules pass `node --check`. The full combined Node test file includes network/process exercises outside this authorization, so I didn't run that full file.

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform -race ./agentsec-api -run '^Test(SecurityAgentExportBrowserReadinessDestinations|SecurityAgentExportAPIProductionComposition|ExportWorkflowConfigurationIsClosed|ComplianceStorageFactoryBoundary)$' -count=1 -v
```

All four top-level Go groups passed in2.310s, exit0. The new readiness test uses an in-memory transport, no socket. The existing composition groups use controlled database/provider boundaries. Native and Linux/arm64 API test binaries compiled offline, exit0, with the final imported store source. They were not executed:

```sh
# From services/platform
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-api -c -o /private/tmp/zasp-export-browser-build-eFkpZH/agentsec-api-native.test
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./agentsec-api -c -o /private/tmp/zasp-export-browser-build-eFkpZH/agentsec-api-linux.test
```

No TypeScript/UI source changed, so this packet didn't repeat UI typecheck/build. A fresh UI build remains a required input to actual browser acceptance. Script lint and scoped whitespace checks passed.

## Complete-file hashes

Inherited dirty changes in the two existing combined files were preserved. A diff against HEAD includes earlier packets, not just this lane.

```text
ae08a604e29e222d0c8804b46eb07a3d7a0d751197a3a6ad7b6ccda206f32433  scripts/production-combined-e2e.mjs
94eb4038a473a68baaa7314d575c1f3fd194628f650897cbff2168a2fca0eaa7  scripts/production-combined-e2e.test.mjs
d8d95c2221fd81cd79d6886094055d5b1f89fa234dfeb9a333740bfe447a3ec7  scripts/security-agent-export-mounted-browser.mjs
8c2587afb911f79589284a80998292498eab1e73d4b385960f936cca07f7a1c4  scripts/security-agent-export-mounted-browser.test.mjs
53152252288054687560636b23f9c31693ddcfed7769272ec12ea33eb81f0238  services/platform/agentsec-api/security_agent_export_browser_process_test.go
8b9704fd4a711bba30b88e5d910a1c9fe18cb4873a6f239ea53b7438c6ee1e1c  /private/tmp/zasp-export-browser-build-eFkpZH/agentsec-api-native.test
5c50fcb3565f8b5e3ca7897557c732b3a633c8cff5b1655dde31d6e847baec18  /private/tmp/zasp-export-browser-build-eFkpZH/agentsec-api-linux.test
```

## P2/P3 review fixes, runtime still held

I verified both review findings against the code, then used receiving-code-review and TDD for this fix round. Only the combined runner, its tests and this report changed. Go, worker, store, UI, SQL and the ledger stayed untouched.

The export lane now keeps every API lifetime's owned handle. Restart and final cleanup await both the stop operation and its completion result, requiring status0 with a null terminating signal. Cleanup rechecks earlier lifetimes, so a failed restart cannot disappear when the same stop operation resolves again. A failed API join records cleanup failure and retains the owned temporary root; other cleanup still runs. Other modes keep their existing API shutdown path.

The manifest's `completed` flag now means all browser acceptance assertions passed, including session cookie, console, proxy, lifecycle mutations and receipt/audit IDs. A failure records its stage without copying assertion values or provider responses. The manifest explicitly says cleanup is pending and points to `cleanup.json`; only final joined cleanup writes that separate result. Successful browser acceptance with failed final shutdown is not a clean run.

Behavioral RED was captured before the fix: nonzero and signaled API completion passed restart and final cleanup; console/proxy/mutation/receipt rejection still wrote `completed:true`; accepted flow had no pending cleanup declaration. The initial VM fixture had a cross-realm array mismatch, which I corrected before recording those RED results. No syntax or import failure counted as RED.

Fresh GREEN:4 helper tests and29 focused combined tests, zero skipped. Six exit subcases cover restart/final status7, SIGKILL and status0 with a non-null signal. Five manifest subcases cover all four late rejection stages and accepted/pending cleanup. The controlled tests execute the actual export orchestration and final cleanup with in-memory process/browser boundaries; they start no child, socket or browser.

```sh
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec scripts/security-agent-export-mounted-browser.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test --test-reporter=spec --test-name-pattern='export browser mode refuses|export callback|export API shutdown|export manifest completion|broad lifecycle orchestration|Security Agent simulation selection|combined API environment|failed checkpoint|combined PostgreSQL startup' scripts/production-combined-e2e.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node node_modules/eslint/bin/eslint.js scripts/security-agent-export-mounted-browser.mjs scripts/security-agent-export-mounted-browser.test.mjs scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --check scripts/production-combined-e2e.mjs
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --check scripts/security-agent-export-mounted-browser.mjs
git diff --check -- scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
```

All exited0. Hashes above are refreshed for the two changed script files. The Go binary hashes still describe the prior offline compilation; no Go build was needed or run in this round. No connected runtime, browser, container or network service started. No commit or push. Hand back for scoped re-review before the controller releases the runtime hold.

## Handoff, still held

The rerun command is `ZASP_COMBINED_E2E_SECURITY_AGENT_EXPORT=true node scripts/production-combined-e2e.mjs`, with cached toolchains on PATH, offline Go settings and fresh `npm run build` output. The first attempt failed. Its release58 pin was fingerprint67a4e601 and checksum78e98a4f; the SQL owner must recalibrate the corrected release and hand off matching pins before any rerun. I did not change those pins.

Actual full middleware/database/worker/UI compatibility, visual screenshots, saved files, process joins and loopback-only traffic still need that run and independent review. This lane doesn't implement the restart audit's eight post-commit process-loss checkpoints. It also doesn't yet add the storage audit's two-successful-tenant artifacts, grant replay/concurrent reuse, grant-to-consume permission withdrawal, read-lease cleanup, or corrupt-object matrix. Those remain separate integration work; the new foreign status refusal isn't a substitute.

No local fixture result closes live Stytch, model pricing/spend, AWS IAM/KMS/S3 or deployed network-policy acceptance. Keep M7A-23's original prerequisites and SHIP-GATE intact. Run the connected candidate only after the controller releases the runtime hold.

## First connected RED, two separate failures

The controller's authorized run reached the author OAuth callback and expected bootstrap scope, then failed before creating a definition. Retained evidence: `/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-security-agent-export-evidence-mDD16R`. Retained owned root: `/private/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-production-e2e-dV2KgD`. I inspected both without deleting or changing them. The manifest says `completed:false`, failure stage `browser-flow`; definition-list and execution-controls GETs returned503, runs/approvals/templates returned200. No export object or download was produced.

The controller traced the primary503 to `zasp_sa_export_principal_ready`: its foreign `zasp_` role test also matched the registered `zasp_e2e_security_agent_api` session user's own login. Both failing actor-bound reads use this SQL guard. Registered SQL RED/fix and pin recalibration belong to the SQL owner, including worker/action and genuine foreign co-membership checks. No product/SQL fix was made in this browser packet.

Cleanup then rejected API completion status null. That's a separate signal termination, not proof of an API exit0 and not a hidden acceptance pass. The first attempt didn't retain the signal or API output, so its exact signal and last runtime stage cannot be recovered from these files.

Using systematic-debugging, I traced `owned-command.mjs`: it passes Node's close status/signal through unchanged, sends SIGTERM, then SIGKILL after its default5000ms grace. Export API inherited `ZASP_SHUTDOWN_TIMEOUT=5s`, leaving no margin for lifecycle work and dependency closing. A socket-free controlled reproduction with actual owned Node children showed a50ms drain returning status0/signal null in53ms, while a5100ms drain returned status null/SIGKILL in5005ms. This confirms the budget hazard and correct owned-command reporting. It does not retroactively prove which signal ended the first API.

The controller approved the narrow correction: export API now overrides its shutdown timeout to1s, as other harness modes already do. The product's SIGTERM path and shared owned-command implementation are unchanged. Each export API lifetime writes `api-lifetime-N.json` before success assertions, with completion availability, status, signal, shutdown elapsed milliseconds, the parsed `runtime_stopped` marker and stdout/stderr byte counts plus SHA256 hashes. No raw output, secrets, DSNs or tokens are persisted. A cached first shutdown attempt preserves the original timing and failure through later cleanup calls.

TDD RED: the selected API environment still had5s, and both actual child outcomes lacked retained completion evidence. GREEN now covers1s configuration for both API lifetimes, actual1100ms graceful drain, actual5100ms forced kill, rejection evidence, sanitized hashes and unchanged first-attempt timing after repeated cleanup. Existing restart/final status7 and signal refusal checks now require their corresponding diagnostic file too.

Fresh verification after this correction:4 helper tests and33 focused combined tests passed, zero skipped. Actual controlled children were created only for the socket-free shutdown regressions; they joined within the test. ESLint on all four JS files, both module syntax checks and scoped whitespace checks exited0. The command selector was the prior focused list with `export API ` covering all shutdown groups. No browser, container, API service or external network was launched in this debugging round; no Go/store/worker/UI/SQL/ledger edit, commit or push. The current two script hashes are above.

Request scoped review of the shutdown correction. Rerun stays held for the SQL fix and matching release pins.

## Connected controlled acceptance, passed

The final connected run exited 0 at release58 fingerprint `8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f` and checksum `5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985`. Retained evidence is `/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-security-agent-export-evidence-RJN0zr`; `manifest.json` SHA-256 is `d911157dcd3131bc6baaeea211149b71b8adf0012aa21f18f5d93ad9a8d238ce` and records `completed:true`. `cleanup.json` records joined cleanup with no errors and no retained temporary root.

The run used the actual migration CLI, public API handlers/repositories, three callback-authenticated browser principals, product planner/dispatch/settlement processors, compliance writer, mounted retrieval and native browser downloads. It created its own definition, controls, activation, run, plan, approval and export. The persisted selection contained the canonical `manual` and `run_audit` sources; both stored record hashes and bodies matched the independently read tenant/run-scoped originals. JSON, CSV and readable downloads completed with distinct browser GUIDs and verified bytes. The restarted JSON download matched the first JSON SHA-256 exactly. The API/worker restart retained the same export and object version, and the foreign tenant received a denial.

Both API lifetimes exited status 0 with no signal after 58ms and 47ms. The earlier SIGKILL was traced to test-only `ownedpgrelay`: a PostgreSQL CancelRequest EOF could not interrupt a blocking inherited stdin read. The relay now transfers stdio to duplicated nonblocking pollable descriptors. Its local, race and Linux/arm64 tests pass 3/3; the exact pgx cancellation/database-close diagnostic changed from a greater-than-two-second timeout to status0 in0.22s. This does not change product runtime code.

The first connected run at the final SQL pin had already uploaded and read back one8,305-byte package, but a stale proof asserted one selected source instead of the product's canonical two. The correction now validates exact order, identities, versions, associations, hashes and original SQL bodies. Strict product-ID/digest/version checks run before either owner query, and malformed values prove zero SQL calls. Independent review accepted both the relay correction and the final evidence validator with no Critical/P2 finding.

This is local controlled acceptance, not live-provider or deployed-production proof. OAuth callback behavior used the owned identity service, planner and S3 transports were controlled, PostgreSQL was disposable, and no live Stytch, OpenRouter, AWS IAM/KMS/S3, Kubernetes/CNI or production deployment was exercised. The later restart packet closes all eight post-commit checkpoints, and the registered storage matrix closes grant reuse/revocation/concurrency, corruption and exact-version read-lease deletion at controlled local scope. Cleanup-worker process retry, a true second-Organization stored artifact, multi-step execution and live/deployed acceptance remain open; see [restart](restart/final-report.md) and [storage matrix](storage-matrix/README.md).
