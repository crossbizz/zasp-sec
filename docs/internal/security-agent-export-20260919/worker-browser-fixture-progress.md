# Worker fixture is ready for the owned browser runner

2026-09-19. The new test-only worker composes the real planner, action, compliance executor and compliance cleanup runtimes. Its child hasn't been launched. Native checks and offline compilation passed; registered/browser acceptance remains open.

I changed only `services/platform/agentsec-worker/security_agent_export_browser_process_test.go` and this report. No product Go, SQL, release pin, existing test, store implementation, UI, script, ledger or deployment edit. No container, external DNS/provider request, commit or push. The controller explicitly authorized one bounded loopback TLS listener for the first RED; its existing helper was closed on return. Later new-fixture tests use listener-free transports and response recorders.

I read the browser, storage/download and restart-continuity audits, then the Superpowers TDD/testing and verification instructions. They shaped the behavioral RED, restricted write set and evidence limits here.

## Frozen with the other owners

Child entry: `TestSecurityAgentExportBrowserWorkerProcess`. The parent invokes exactly that selector in its compiled worker test binary. No standalone SKIP counts as process proof.

Every variable below has prefix `ZASP_SA_EXPORT_BROWSER_`:

| Suffix | Required value |
| --- | --- |
| `WORKER` | Literal `true`; absent skips the child entry, another value fails. |
| `PG_PORT` | Canonical decimal1024..65535. |
| `DSN` | Exactly shaped `postgres://zasp_e2e_security_agent_worker@127.0.0.1:<PG_PORT>/postgres?sslmode=disable`. No password, foreign host/login, alternate query, fragment or mismatched port. |
| `WORKER_PORT` | Canonical decimal1024..65535, distinct from PG_PORT. |
| `DEADLINE` | Absolute RFC3339Nano timestamp, more than one second and at most30 minutes ahead. |
| `OBJECT` | Canonical absolute directory `<owned-root>/export-store`; parent basename starts `zasp-production-e2e-` with a nonempty suffix. Store code checks resolved parent and ownership marker. This is a directory, despite the retained variable name. |

The worker starts first. It calls `exportfixture.Create` only if OBJECT is absent, otherwise `Open`; API opens the same store after readiness. Frozen config: bucket `zasp-compliance-exports`, owner `123456789012`, KMS ARN `arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111`, maximum package8MiB. The sibling storage owner owns `internal/exportfixture`, its multi-object state and request log. This file only consumes its API.

The shared store exposes `state.json` version1 and `requests.jsonl`. Objects retain full key/version/body/headers; requests distinguish before/stored/response and PUT attempts from object creation. Worker `Close` preserves those files for API access and process restart. The harness owns final removal after every borrower joins. No store removal runs in this child.

The planner and action compositions connect as `zasp_e2e_security_agent_worker` and `zasp_e2e_security_agent_action`. Writer and cleanup use `compliance_executor` and `compliance_cleanup`. No owner query is emitted, and no accepted plan/package/receipt is synthesized in SQL. AWS SDK uses `https://controlled.invalid` with an injected disk transport, anonymous SDK credentials, separate controlled role identities and no default-network fallback; no IRSA file is read.

## Listener contract

The child listens only at `127.0.0.1:<WORKER_PORT>`. It rejects non-loopback peers, query strings, request bodies, unknown routes and unknown hosts. All accepted operations have a ten-second child deadline linked to request and process cancellation; a bounded semaphore serializes operations. HTTP read/write timeouts are12 seconds, header/idle timeout one second, headers4096 bytes.

GET `/readyz` with each fixed Host calls that composition's actual `Ready`:

```text
agentsec-security-agent:8081
agentsec-security-agent-action:8081
zasp-compliance-export-worker:8081
zasp-compliance-cleanup-worker:8081
```

The exact listener Host runs all four checks for parent startup. Every other Host fails. Ready replies use the production API probe contract: `Content-Type: application/json; charset=utf-8`, body `{"status":"ready"}\n`. They aren't constant-health replies.

POST controls accept only the exact listener Host. `/plan`, `/dispatch` and `/settle` call the Security Agent processor's real `RunOnce`; `/capture` calls the compliance executor; `/cleanup` calls the cleanup runtime. Export dispatch belongs to the Security Agent processor, so action composition is present for its real readiness requirement. A phase name doesn't select SQL or manufacture state: the processor chooses work from persisted authority. Browser orchestration must assert the resulting run/job state.

The optional unselected manual canary should be created after settlement, before download, or omitted. A queued canary present during `/settle` can be planned by that same real tick after reconciliation. I sent this constraint to the browser owner; the phase label doesn't suppress ordinary claim behavior.

Success is200 with JSON `{"ok":true,"phase":"/plan"}` (phase varies). Product errors become503 with a fixed public message; database details aren't exposed. On SIGTERM/interrupt the server cancels active work, shuts down and joins, then closes all runtimes/store/database handles. Deadline exhaustion fails the child. Child signal/join behavior is implemented but not exercised in this native checkpoint.

## RED happened at the real parser

First `TestSecurityAgentExportBrowserPlannerSelection` used the unchanged `newCombinedE2EOpenRouterPlanner(false)` with a valid manual export context and asserted a parent-run target plus exact typed selection. Controlled loopback request count was1. The production parser returned `planner_rejected`, no candidate, exit1 in1.054s:

```text
FAIL: public manual export candidate rejected or changed
Failure:planner_rejected
Candidate:{Version:0 Summary: Steps:[]}
calls=1
```

That shared helper targets the evidence digest and omits export `evidence_ids`. No change was made to it. The new `exportBrowserPlannerTransport` parses the real outgoing request and context, requires one export action with target equal to the actual parent, then returns one step carrying the exact ordered typed selection. Production request preparation, parser and candidate validation remain active. The test passed in1.057s after the local transport was added.

Response usage is controlled120 prompt/40 completion/160 total tokens,100 nano credits. `budgetFixturePlanner` binds that prepared request to the existing controlled cost policy with maximum1000 tokens/200 nano credits. The real processor still reserves and settles its budget before planner acceptance. A new actual-processor component test reaches acceptance with one provider call, exact manual selection, no execution and no planner failure; its authority is controlled, so it isn't registered PostgreSQL proof.

Separate environment/phase tests first failed against disconnected fixture functions, exit1 in0.971s. After wiring them, three groups passed in1.064s. Reviewing the production readiness client exposed its strict response-body contract; adding that assertion produced another behavioral RED, exit1 in1.110s, because generic phase JSON was refused. Ready replies were corrected locally. No product change was needed.

## Commands and fresh results

All Go commands ran from `services/platform` with Go1.25.6 darwin/arm64 and this prefix:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go
```

First RED suffix:

```sh
test ./agentsec-worker -run '^TestSecurityAgentExportBrowserPlannerSelection$' -count=1 -v
```

Focused race GREEN: five top-level groups, zero skips, exit0 in2.105s:

```sh
test -race ./agentsec-worker -run '^TestSecurityAgentExportBrowser(Environment|PhaseRouting|PlannerSelection|PlannerRuntime|ControlRefusals)$' -count=1 -v
```

Affected race GREEN:28 top-level groups, zero skips, exit0 in6.311s. Includes shared browser/agent compliance processing, typed planner authority, dispatch, settlement retries and manual provenance:

```sh
test -race ./agentsec-worker -run '^(TestSecurityAgentExportBrowser(Environment|PhaseRouting|PlannerSelection|PlannerRuntime|ControlRefusals)|TestSecurityAgentExport(Planner.*|DispatchProcessor|Polling.*|Worker.*)|TestSecurityAgentManualPlannerPreparedIdentity|TestCompliance(RuntimeConfiguration|RuntimeComposedLifecycle|ReplayOutcomes))$' -count=1 -v
```

Offline compilation: `test ./agentsec-worker -run '^$' -count=1` exited0 in0.864s (no tests selected, compilation only). Then `test ./agentsec-worker -c -o /private/tmp/zasp-export-browser-worker.bRbt5X/worker.test` exited0. The directory came from `mktemp -d`; its unlaunched binary is retained for the integration owner. No subprocess test was accidentally selected. Whitespace check against `/dev/null` for the new Go file passed.

After the storage owner's final freeze, I checked `store.go` SHA-256 `c8413ae38d5fd4ed025c4f99472b6b0ea25ef984f4c44095a588e50fcb84a491` and `store_test.go` SHA-256 `9cef0eed9729f2bc6b9725d2743a2d0269fb652e96adda2199b99ec09737dbe7`, then repeated that offline binary compile. Exit0; binary hash unchanged. I didn't edit those dependency files or rerun the sibling's storage tests.

```text
912582225f69eadcb81b6f8a31b5bcef2da1f10f5f1c89f2777a44944ddddcf0  services/platform/agentsec-worker/security_agent_export_browser_process_test.go
12e1a79a36a02db19a59f77078274ba9c9dad52c2fa6e0d561f44b942d7d37dd  /private/tmp/zasp-export-browser-worker.bRbt5X/worker.test
```

This binary is a local integration input, not a production build. The browser owner still owes real child startup, registered four-service readiness, public plan/approval/dispatch/capture/settlement, saved native downloads and clean process joins. The separate restart packet remains open. Freeze the sibling store/API/harness inputs before running that connected batch.
