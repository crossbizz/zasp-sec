# A-H and the affected registered batch pass

Final reviewed restart candidate: **PASS,92.66s**. Root independently reran A-H in92.63s and the corrected broad registered selector exited0. Both browser-origin compliance regressions passed too. Native race:121 top-level tests passed across three packages; two rendered-deployment fixture checks skipped because their input manifests weren't supplied. This packet doesn't claim a clean launch gate.

Only the three allocated Go test files and this evidence directory were written. Product SQL, release pins, production code, the ledger and unrelated dirty changes were left alone. Nothing was staged, committed or pushed.

## What the process proof observed

One public-created definition and manual run crossed A-H. Thirty-five API/worker children joined. Seven deliberate post-commit exits returned86: A, B, C, D, F, G and H-consume. E used SIGTERM and the actual uncertainty/retry path, then exited0; the replacement waited the real30s retry deadline and claimed generation2/attempt2. Settlement also waited its real30s dedicated lease, without changing database timestamps.

The final run retained one accepted plan, one step and independent approval, one model call, one settled reservation, one export link/job/effect, two conditional PUT attempts and one immutable object version. Recovery made one empty-payload prepared load, zero capture calls and zero fresh prepare mutations. Both stale export generation/token and stale settlement token hit their exact40001 lease fences. The actual Security Agent RunOnce settled the parent once to `needs_human/export_available`, with succeeded step/effect and one parent-version increment. A fresh worker then left retained settlement/accounting facts unchanged.

H receives a plaintext grant response before the issuing API exits. A new API process reads the same stored format. For the second grant, the synchronous response observer recorded `header_writes=0`, `body_writes=0`, `body_bytes=0` at the committed consume checkpoint, before abrupt exit. Reusing that token failed; a fresh authorized grant recovered identical bytes. The1186-byte download SHA-256 is `394ea1ee92ca07d42359fd002d1f9e2cab4e2245f38b3af461d6b2e8d018f7a2`.

These are real OS child processes, registered SQL and production worker/router/retrieval composition. Identity middleware, model responses and persistent AWS SDK transport are controlled. Durable session, CSRF and current membership checks remain active. API requests run through the mounted router in a child-local HTTP recorder; this doesn't prove a network listener, live provider storage or a browser-native save. The saved bytes aren't a live deployment claim.

## Commands and retained results

All Go builds used `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`, `/opt/homebrew/bin/go` and the shipping worktree. The operator compiles Linux arm64 with CGO disabled, uses the pinned local PostgreSQL image with `--pull=never --network none`, then runs the exact selector. Full argv/environment overrides and all1632 platform source-file hashes are in the matching JSON, not inferred from HEAD.

```text
node docs/internal/security-agent-export-20260919/restart/run.mjs
  focused pre-review A-H PASS95.79s

ZASP_RESTART_SELECTOR='^(TestSecurityAgentExportPublicRestartPostgres|TestComplianceHTTPPostgresGrantLifecycle|TestComplianceRuntimePollingPostgres)$' node docs/internal/security-agent-export-20260919/restart/run.mjs
  final A-H PASS92.66s; compliance grant PASS6.43s; compliance polling PASS11.79s
  exit0

ZASP_RESTART_SELECTOR='^Test(SecurityAgent(ExportPublicRestart|ExportDefinition(Receipt|PublicLifecycle|AuthorityWait|Predecessors|HTTP)|Export(Release|Lifecycle|Authority|StoppedSettlement|SettlementInterleave|WorkerProcess|PlannerAdmission|PlannerAccounting|AccountingAdmission|AccountingStops|Approval|ApprovalRefusals|NonExportRoute)|Manual(Admission|HTTP|ClaimIsolation))Postgres|ComplianceLifecyclePostgres)$' node docs/internal/security-agent-export-20260919/restart/run.mjs
  corrected affected batch PASS,0SKIP; exit0
  run-2026-09-20T01-27-04.010Z.log/.json

node docs/internal/security-agent-export-20260919/restart/native.mjs
  native exact selection:123;121PASS,2SKIP; exit0
  apiserver21.957s, agentsec-worker9.716s, agentsec-api2.611s
```

The broad selector's `ComplianceLifecyclePostgres` alternative matches no existing test. The focused run explicitly selected the actual compliance grant and polling names above. The first registered batch exposed a stale Attack Lab fixture. Its correction uses registered definition/control/activation and planner Reserve/Settle operations; no production code or release pin changed. Root then reran the same broad selector from current source and it passed.

Final focused evidence is frozen as `final-run.log`, `final-run.json`, `final-summary.json`, `final-download.json`, `final-cleanup.json`. The original timestamped pair is `run-2026-09-20T01-03-26.460Z.log/.json`. The historical grouped failure is `run-2026-09-20T01-04-59.602Z.log/.json`; the corrected grouped pass is `run-2026-09-20T01-27-04.010Z.log/.json`. Use the timestamped pass for the affected registered result.

The race output and exact selection are `native-race.log`, `native-race.json` and `native-selection.txt`. Two skips are only `TestComplianceDeploymentRenderedWorkerConfig` and `TestComplianceDeploymentRenderedAPIConfig`. Those checks remain uncovered here. The initial overbroad native selector, shared-memory failure and timeout remain in `native-race-prior.log/.json`; cleanup is documented in `native-cleanup.md`.

## The stale route fixture is corrected

The first broad run found that the inherited Attack Lab fixture had no immutable definition version and no settled planner accounting. Release58 correctly refused it. The test now creates history through registered definition/control/activation operations and uses the real repository Reserve/Settle path before acceptance. Release57 behavior and the existing refusal cases remain intact. Independent review accepted the test-only correction with no Critical/P2 finding; raw correction logs weren't retained, so root reran the frozen current binary. See `attack-lab-route-fixture-correction.md`.

## Frozen hashes

Paths below are relative to this shipping worktree. Installed/compiled58 checksum is `5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985`; fingerprint is `8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f`.

```text
a1ccfd0563d68ee6961998af556de2d58b3465f6b148dfe8a40cdab1b4fce242  services/platform/apiserver/security_agent_export_public_restart_postgres_test.go
e8d8163b32d5b192c09a9b2565e8281c4fc06845d31720f018630a59e0105625  services/platform/apiserver/security_agent_export_public_process_test.go
6850eabb13628085a347ef75a860a3931d8bd7920aae6128b46ce876dbd31e5b  services/platform/agentsec-worker/security_agent_export_public_process_test.go
043c548673b28d64f8debadf7d18e6d9c511b5add91818db521d9ba581ed539c  final api.test
141c4fc00f6501833568d77aa97544642cdca0b07d417697a19e738540889be3  final worker.test
cebff288d2d4b5ea55a265e0fdaf68abf2b278fabf9e7c0b6b99f7d84f6e5d23  final-run.log
d4a87584c214e7598160ac59f03154147a4e5f816c1517df738b2cc7eabb9e24  final-run.json
310c234872da2d446cc2599e7e2b3ffa1a459f1d2f3f32f67e4093d9c4e28441  final-summary.json
394ea1ee92ca07d42359fd002d1f9e2cab4e2245f38b3af461d6b2e8d018f7a2  final-download.json
5bad83260e13576b4872172c68407ad3a6c917319273a603c8fbde7837809218  native-race.log
7df59339aae7e0f3babe731aa4bd00d11294bf75f9301e9c6bf6599b456ae332  run-2026-09-20T01-04-59.602Z.log
ade0f1c119bb7124c9d6998ce3b7bbdcc8d88a1869d7902680c820ff6892e99e  services/platform/apiserver/security_agent_export_approval_route_postgres_test.go
85aa5e2c0d68a6482887408c3336cbe2a2f854de485fcfda8283cbf405dce913  services/platform/apiserver/security_agent_attack_lab_postgres_test.go
5011adcd24a6dfb4228c2e5d149be4ca9a9f47f538c0f7e52de6c67bf2905d11  run-2026-09-20T01-27-04.010Z.log
c93df91c2756d7ca95d6d18f8a0d51b4382dfd13edb88c0171d539115949b25d  run-2026-09-20T01-27-04.010Z.json
ce50fbcdbac484cc7b16e495a09648a749748d42d595be6ac60657f28c80f2b2  operator-cleanup.json
```

All owned container PostgreSQL lifetimes logged normal joined shutdown. Both operator binary directories are absent, and inspection confirms the final owned container is absent. Request envelopes and raw grant/lease tokens were confined to each disposable test directory. The one native-timeout directory was moved to Trash and remains recoverable; no native PostgreSQL process remained. The three Go files are frozen for independent review.
