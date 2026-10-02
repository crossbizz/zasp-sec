# Task 5: compliance UI and connected acceptance

Status: implemented and source-frozen for independent review, with an unresolved post-denial session/UX concern. Not live-production-ready.

## Outcome and unresolved concern

The UI binds real source detail, export jobs, grants and downloads. Typed selectors preserve kind, exact version and current selected organization/workspace/environment, accept policy-* IDs and never route generic audit IDs to Security Agent detail. Authoritative SQL aggregate freshness is displayed directly; absent optional freshness is explicitly legacy compatibility, not current authority. Session/retention surfaces remain intact.

Exports use current principal/scope/session gates, fresh authentication, bounded attachments (4 MiB default), body-only transient grant tokens, deterministic errors and job-ID-only reload recovery. Evidence remains readable on export/download failure.

The connected local browser's asserted core flow passed through actual registered PostgreSQL/session auth, mounted production API, actual polling worker and persistent versioned artifact adapter. Native JSON/CSV/readable downloads matched persisted bytes, worker/API restart and page reload recovered the job, source changes were detected, sibling and foreign requests returned404, and grant replay was refused. This is controlled local provider evidence, not AWS.

**Open connected-review concern:** the final screenshot unexpectedly shows sign-in after sibling-scope/foreign-denial checks. Those404 assertions and earlier downloads/restart passed, but final session continuity was not asserted. Final URL, per-request response trace and console state were not retained, so the sign-out cause is unknown. Do not credit the screenshot as mounted compliance visual proof or describe sign-out as expected. Root requested independent review and a focused continuity rerun, with a screenshot while controls/export are mounted. Source stays frozen pending that scoped review.

## Frozen source and scope

- Worktree: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917
- Branch: codex/cached-runtime-ship-20260917
- HEAD: 8733b16f8d939d38a8157dd2519e57fc6f630542
- Dependency lock Git blob: f19911ce997d2b26a14948a9230bbc66b28e0094
- Node22.23.1 and Go1.25.6 darwin/arm64; local/offline Go configuration.
- [task-5-blobs.json](task-5-blobs.json) is the authoritative complete23-file BEFORE/AFTER manifest. BEFORE blobs are working-tree captures, not HEAD, preserving inherited Task1–4 and unrelated work.
- [task-5-scoped.patch](task-5-scoped.patch) is exactly that delta. Reverse apply --check passed against frozen working files.
- task-5-before.json is an early partial capture only, superseded by the complete manifest.
- No staging, commit, push, release55 change, root ledger edit, host PostgreSQL server, live provider request, image pull/build, advisory lookup or subagent dispatch.
- Source unchanged after manifest creation. Only reports/evidence packaging continue.

The manifest includes selector/view/API adapter/tests; SessionsComplianceView and ZaspProductionApp integration; additive runtime factory/test-only browser process; shared client; availability map/five contracts; combined harness/tests, byte extractor and package entrypoint.

The runtime seam preserves existing production wrappers and default newComplianceStorageResources. Only a Go test process selects the controlled read transport, allowing GET/HEAD for the exact persisted owner/version/object. Actual mounted handler/artifactstore/s3driver and actual worker run; there is no environment-selectable production mock. API reader role remains separately configured.

Unchanged audit tests exposed an unconditional await in Task4's shared download classification, delaying ordinary physical dispatch before abort boundaries. Task5 captured client BEFORE084bb4cd8006c4798aecc6a2b1d3f35bf4abd23d and now classifies synchronously, awaiting body parsing only for compliance downloads. Existing abort assertions remain unchanged and pass; strict attachment and cancellation checks remain.

UI/API map now has159 actions:147 available,10 API-only,2 planned. All seven compliance actions are available. Contracts now require the mounted endpoints, freshness and export UI, not obsolete unavailable behavior.

## Original task coverage

| Original IDs | Local evidence and limits |
| --- | --- |
| M7-08/09 | Task1 current-source model/assembler reused unchanged; grouped SQL and UI stale/missing/fresh projection. Product IDs, not screenshots, bind evidence. |
| M7-10/11 | Task4 mounted list/read contracts reused; real control/evidence/detail reads. Current aggregate freshness stays authoritative, including Task4-fix1 >100-source regression. |
| M7-12/13 | Real create/status, selected framework/control, queued/completed/error/expiry UI, durable restart recovery and SQL denials. |
| M7-14 | Real worker stores package through versioned storage adapter. Native JSON760bytes, CSV568bytes, readable770bytes match persisted members. Raw JSON extracted without reserialization. Exact source/version/timestamp, metadata omission and no affirmative certification language asserted. Live S3/IAM/KMS remains open. |
| M7-15a/b/c | Framework/control filters, typed links/timestamps, stale/missing state; generic audit routing and strict/foreign selector tests; browser policy version7 click and later source_changed. |
| M7-15d/15 | Real export/status and one-use grant, all native formats, API/worker restart/page reload, foreign selector no scope switch and sibling/foreign404. Post-denial session continuity and mounted visual proof remain unresolved. |

Task1–4 reports retain broader source-kind, privilege, quota, bounded-export and storage evidence. The1000-policy Production scope was left unchanged. Authorized Staging supplies bounded one-control/one-policy success; it does not replace quota/oversize denial tests.

## Exact verification

Logs retained under [task-5-evidence](task-5-evidence/). Commands run at worktree root unless noted. Node uses /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node. Go uses /opt/homebrew/bin/go with GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache. Browser PATH prepends the Node22 directory, /opt/homebrew/bin and /usr/local/bin. Docker is /usr/local/bin/docker.

Focused RED/GREEN:

- Selector20 behavioral RED then GREEN; selector-red.log and final full-suite GREEN.
- Initial UI9fail/5pass for typed sources, aggregate freshness, filters/jobs/reload/denials; ui-red.log. GREEN in final full suite and earlier affected74-test batch.
- Actual soc2_security framework fixture exposed/fixed display-to-input normalization.
- Factory first had compile RED, then behavioral RED when a stub bypassed injection; real seam passes explicit race selection. Earlier bounded tool output was not saved as a full factory RED log.
- Additional adapter/byte-extractor tests were added after implementation; not claimed as initial TDD RED.

Connected dispatch RED command (8failed/122passed, connected-dispatch-red.log):

~~~sh
node node_modules/vitest/vitest.mjs run app/api/APIProvider.audit-exports.test.tsx apps/web/api/audit-log.test.ts app/features/sessions/SessionsComplianceView.test.tsx app/components/ZaspProductionApp.test.tsx app/features/sessions/compliance-api.test.ts app/domain/compliance-links.test.ts --reporter=dot
~~~

Connected GREEN command (79passed, connected-dispatch-contracts-green.log):

~~~sh
node node_modules/vitest/vitest.mjs run app/api/APIProvider.audit-exports.test.tsx apps/web/api/audit-log.test.ts apps/web/api/compliance-download.test.ts app/quality/m7-session-compliance-batch-contract.test.ts app/quality/m2-closure-contract.test.ts app/quality/m2-identity-governance-ui-batch-contract.test.ts app/quality/ui-api-map-contract.test.ts app/quality/ui-api-coverage-ci-contract.test.ts --reporter=dot
~~~

Final assembled commands, all exit0:

~~~sh
node node_modules/vitest/vitest.mjs run --reporter=dot
node node_modules/typescript/bin/tsc --noEmit
npm run lint
npm run build
node --test scripts/production-combined-e2e.test.mjs scripts/owned-browser-postgres.test.mjs scripts/compliance-browser-bytes.test.mjs
node node_modules/eslint/bin/eslint.js scripts/production-combined-e2e.mjs scripts/production-combined-e2e.test.mjs
~~~

UI224files/2086tests pass. Node82tests:80pass,2skip,0fail. Skips are existing opt-in real SIGTERM cleanup tests for combined runtime provider containers and composed Red Team containers, not compliance coverage. Final harness-only node/lint ran after its last fixture correction; UI/type/build source unchanged afterward.

Build initial concurrent clean-output failed ENOTEMPTY; exact competing writer not established. Serial retry passed all build phases without source changes. Initial build log is diagnostic. Earlier full-suite failure included next/link resolution from an intermediate lint adjustment plus obsolete contracts and connected dispatch failures; all resolved in final2086-pass run.

Exactly3 non-SQL Go cases enumerated BEFORE race, from services/platform:

~~~sh
/opt/homebrew/bin/go test -list '^TestCompliance(StorageFactoryBoundary|APIProductionComposition|APIConfiguration)$' ./agentsec-api
/opt/homebrew/bin/go test -race ./agentsec-api -run '^TestCompliance(StorageFactoryBoundary|APIProductionComposition|APIConfiguration)$' -count=1
~~~

Enumeration and race exit0 (race1.957s); go-test-enumeration.log / go-race-accepted.log.

Grouped SQL used unchanged reviewed Task4-fix1 Linux arm64 test binaries. API SHA2565009418aa052f176c3c44129582e80d68ad36fa2ccd338cdef9fd5fc8ff69cd5; worker SHA256cfdb7894a0b45d9fa66934c6cf753f864056b2f5088472782b86c4614149c2c5. Source/repository dependencies are unchanged since their accepted Task4-fix1 identities. Earlier group40252 exit0; its full tool output was truncated, so identical group95214 ran solely for full log retention.95214 joined exit0; full output retained as task-5-evidence/sql-accepted.log. All task-owned process handles are joined.

~~~sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task5-retained --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task4-fix1-worker.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance' -test.v -test.timeout 240s
~~~

This is the full connected compliance SQL source/job/quota/grant/API/worker/replay batch, not all-repository SQL. Helper-only process skips are launched by parent tests as needed. All SQL executes inside owned cached Docker, network-none; host client tools only, never host PostgreSQL server.

Connected browser command:

~~~sh
ZASP_COMBINED_E2E_COMPLIANCE=true node scripts/production-combined-e2e.mjs
~~~

Handle18576 exit0, browser-core-accepted.log. Job pid_b348bcdc-9710-40ce-bcaa-77df9fcc6852; persisted package SHA25643ff3e89b9c67ad4d93bca33913ad157acfd651a361669521f4b9710e0efef6a. Both actual worker processes joined after SDK PUT. API restarted against same DB/object; same-tab reload restored job and unchanged native bytes. All browser/API/web/owned PostgreSQL processes joined. Unrelated voxeval containers remained untouched. Native files, object envelope, summary and diagnostic screenshot copied into task-5-evidence/browser-artifacts; original /tmp/zasp-compliance-browser-mgcz4i retained.

## Modes, diagnostics and self-review

Normal production:combined-e2e package command now requires existing default mode AND release56 compliance mode. New acceptance cannot silently disappear. Default release48 is explicitly legacy disabled-service compatibility; both old before/after-restart assertions say so. It was not rerun or credited as current compliance acceptance.

Five earlier browser attempts are separate diagnostics:

1. Timestamp fixture expected no fractional seconds.
2. Production1000-policy scope exceeded export control bound; success moved to authorized Staging without changing Production.
3. Native JSON absent because synthetic target replacement discarded download configuration.
4. Exact native JSON passed; synthetic new target discarded sessionStorage, breaking recovery.
5. Native formats/restart passed; foreign fixture lacked schema-required session- prefix.

Fixes preserve real downloads and same-tab reload; no fabricated success or fetch-only replacement for native UI download. Minimal owned Chrome diagnostic confirmed page-session download behavior and was joined. These five attempts are not accepted proof.

TDD, verification and systematic-debugging skills guided behavioral failures and grouped checks. Strict source identity/version, permission/fresh-auth boundaries, token confinement, bounded bytes, persisted replay and stale-response suppression were checked. Connected client regressions were fixed rather than called inherited.

Remaining gates:

- Unexpected post-denial sign-in and missing mounted screenshot require independent connected review/focused evidence.
- Task4 deferred Minors remain open: provider-read versus integrity_failure categorization across artifactstore/s3driver, and noisy composition telemetry. Neither is silently claimed fixed.
- Live AWS reader/worker IAM separation, KMS/Object Lock/lifecycle, deployed release/readiness, operational provider network policy and external advisory gate remain open.
- No ledger completion or release-ready claim. Root owns independent review and original-ID attribution.
