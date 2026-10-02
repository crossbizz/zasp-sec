# M7A-23 worker batch, in progress

Registered process fixture added in apiserver/security_agent_export_worker_process_postgres_test.go.
It reuses the database implementer's stable runExportDBFixture and actual
RegisterComplianceWorkers/dispatch, then launches existing actual worker binary
for interrupt/resume with controlled SDK transport. Prerequisite plans remain
owner-seeded component fixtures. Native compile-only check passes; no tests run
in that compile check. The first owned-container execution reaches release58
worker registration and fails with invalid migration state. Retained output:
process-registration-red.txt. Test/container exit1; owned PostgreSQL shutdown
joined normally, exit0. No child worker lifecycle was reached or proved.
Database implementer notified; registration/readiness work is already in scope.

Execution details: crosscompile both ./apiserver and ./agentsec-worker test
binaries with GOOS=linux GOARCH=arm64 CGO_ENABLED=0 and the cached Go environment
below, into mktemp /private/tmp/zasp-export-worker.XXXXXX. Docker runs cached
postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba,
--rm --pull=never --network none --read-only --user postgres --cpus2 --memory2g
--pids-limit512, owned executable /tmp tmpfs1400m and /var/run/postgresql tmpfs.
Read-only binaries mount at /export.test and /compliance-worker.test; worktree
mounts read-only at /workspace. Entrypoint /export.test, working directory
/workspace/services/platform/apiserver, arguments
-test.run '^TestSecurityAgentExportWorkerProcessPostgres$' -test.v -test.timeout300s.
This is registered PostgreSQL integration, not Go race or live provider proof.

Scoped re-review completed: both P3 coverage findings ADDRESSED, no new
actionable defect. Reviewer verified exact fix patch/test/source hashes and
retained mutation/race evidence. Core worker code review is clear; registered58
and real-process acceptance remain open, so Task1 is not marked complete.

Review coverage fixes implemented in one new test file. Literal malformed-key
and in-flight heartbeat/ingress-copy tests pass under-race (2 PASS,0 SKIP).
Deliberate temporary ingress-copy removal makes the new ownership test fail;
exact production bytes restored and final affected-race rerun passes. Report:
review-fixes.md. Scoped re-review requested; full worker acceptance remains open.

Review returned: no confirmed implementation defect; two P3 test gaps for
literal duplicate/unknown wire keys and processor-ingress/heartbeat binding
ownership. Full findings and unverified boundaries: review.md. Address both
before final worker acceptance, with affected tests and scoped re-review only.
Registered58, real process restart and connected-product gates remain open.

Independent read-only component review dispatched to
/root/evidence_export_worker_review (GPT-6 Astra high). Frozen five-file diff:
worker-review.patch, SHA256
1f1415bfde2ad13e4cf98d3e47f9797fcda316b8e85b409551a9b03fadfa8887.
The diff compares captured before blobs and two new files, not inherited branch
changes. Reviewer receives this report and retained RED/GREEN/race evidence;
no duplicate test run requested. Registered58 and OS-process acceptance remain
open and cannot be inferred from this review. Root leaves reviewed worker files
unchanged while review runs.

Newest checkpoint: actual processor now selects the origin-specific renderer,
and lease snapshots deep-copy run/selection binding. Behavioral RED is retained
in red-processor.txt (exit1): agent pipeline stopped before Put and a consumer
mutated owned lease authority. green-processor.txt passes both top-level tests
after implementation. The pipeline uses the real processor/render/prepare/store
bridge with controlled database/storage boundaries; a fresh processor reloads
prepared bytes despite an unusable source response. This is not OS-process or
registered-database restart proof.

Grouped native race command from services/platform, same environment below:

```sh
/opt/homebrew/bin/go test -race ./agentsec-worker -run '^(TestSecurityAgentExportWorker.*|TestComplianceWorker.*|TestComplianceReplayOutcomes|TestComplianceRuntime.*)$' -count=1 -v
```

green-worker-race.txt: exit0,15 top-level PASS,1 SKIP. The skipped
TestComplianceRuntimeProcess is an owned-parent subprocess entry and is not
acceptance evidence. No race warning reported. The executed cases include
existing composed lifecycle/cancellation/lease-loss/revocation, both origin
pipelines, exact prepared replay, unknown Put/Finish outcomes and binding copies.
git diff --check passes. Registered58 integration and independent review remain
open, as do API/planner/settlement/UI/production gates.

Before copies newly added for this checkpoint:
- compliance_export_runtime.go.txt:b2a6cc4e66b42c521ea5fec667f08c3fc643d0ce3b626b5363f2322045a69750
- compliance_export_replay.go.txt:84b1c5241280e58a96aed165a0c1c12b2c45b5e3a5d586b4a7a83dd396fb91e2

Current checkpoint hashes (supersede historical hashes below):
- compliance_export_database.go:f657853ee1b4f103238a5ca0e7a3b75be33f5e3784030a25d876c34e18091266
- compliance_export_runtime.go:f7e4cfbd86dd96c24b84599b16499ad7203e7905e02152571cbb88a47fab4068
- compliance_export_replay.go:cefa1036cbad65b1396e60ca4a65504718612b40561fa8720a557d3d3e168097
- security_agent_export_worker.go:abdf9ed4191f10ec878e0b5c522ca3e8de51c6f22663c8e03196dca673534615
- security_agent_export_worker_test.go:4fd2a83abb9f6b08dd8a9e13747805c3a910eae287bbe92d52f941ae226f4971

Latest checkpoint supersedes the claim-only limitations below: Capture now
validates origin-specific closed snapshot and independent run/step/selection
binding while preserving exact hashed bytes. Prepare and LoadPrepared require
the renderer revision matching the validated lease origin. Both browser and
agent unions reject malformed authority before mutation. The actual processor
still uses the old browser-only renderer callback; routing/replay integration
and heartbeat binding copy are next, so no runtime enablement is claimed.

Additional observed RED: red-capture-prepared.txt exit1, valid agent capture and
prepare refused and wrong browser revision accepted under an agent lease.
Command: same cached Go environment as below, go test ./agentsec-worker -run
'^TestSecurityAgentExportWorker(CaptureBinding|PreparedOrigin)$' -count=1 -v.
After implementation, go test ./agentsec-worker -run
'^(TestSecurityAgentExportWorker|TestComplianceWorker|TestComplianceReplay)'
-count=1 -v passed exit0 (green-capture-prepared.txt):8 top-level tests passed,
1 subprocess entry skipped because its owned parent harness was not launched.
That skip proves no process restart; registered parent-driven restart remains
required. The checks cover byte equality, scope/run/step/selection mismatch,
unknown/missing origin binding, cross-origin mapping/revision and corrupt hash.
The earlier source hashes below identify the previous checkpoint, not these edits.

Root owns worker Go files. Database implementer owns additive58 and registered
database tests; neither edits the other's files. This non-overlapping execution
supersedes the initial sequential implementation rule to reduce handoff time.
No runtime enablement, publication, production claim or task completion.

Base HEAD8733b16f8d939d38a8157dd2519e57fc6f630542.
Before copy: before/compliance_export_database.go.txt, SHA256
61f9e7e0ed44f3b38947845d3a97bcd0862d2221ce7172bb277beb9ace334d8d.
The two security_agent_export_worker Go files were newly created in this batch.

Implemented so far: closed browser/agent claim union, independently decoded
run/step/ordered selection binding, canonical kind/ID/version/digest checks,
duplicate refusal, and64KiB claim bound permitting100 selected records.
Browser wire shape remains unchanged. Capture and preparation still reject
agent-specific revisions, so the renderer is not connected to execution yet.

Verification from services/platform, environment GOTOOLCHAIN=local GOPROXY=off
GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache:

```sh
/opt/homebrew/bin/go test ./agentsec-worker -run '^TestSecurityAgentExportWorkerClaimUnion$' -count=1 -v
/opt/homebrew/bin/go test ./agentsec-worker -run '^(TestSecurityAgentExportWorkerClaim|TestComplianceWorker)' -count=1 -v
```

First command: red-claim.txt exit1, actual valid agent claim rejected by old
decoder, existing browser case passed. After implementation the same command
passed, green-claim-initial.txt exit0. Second command: green-claim.txt exit0,
5 top-level tests including100/101 distinct-selection boundary, immutable
binding assertions and existing persisted-byte/cleanup/heartbeat regressions.
No test skipped. These use a controlled QueryJSON response, not registered DB
authority. Native race and connected database evidence are still pending.

Current hashes after this checkpoint:
- compliance_export_database.go:809a896f0de718a616ffb5e1bda036faf3cad1c9f6c648824e1edc65cbaf53ec
- security_agent_export_worker.go:b1485a0a017b3df90f62e84309e239a7a4d252b916b5c8c0f66d29be4e5cd7a4
- security_agent_export_worker_test.go:609e7dab5a1fc303cdaf6d94e9929ff6a73f373004ca5da26d7a87e5d9c387da

Next: capture schema/binding, origin-specific prepared revision, actual renderer
dispatch and replay/uncertainty, heartbeat ownership copy, grouped native race,
registered58 acceptance and independent frozen-batch review. Plan:
docs/internal/2026-09-19-security-agent-export-worker-plan.md.
