# Task3: worker and storage are ready for review

DONE_WITH_CONCERNS. The implementation and local acceptance are complete.
The concerns below are external gates and the explicit evidence limits, not
claims of deployed AWS acceptance. Root owns independent review and integration.
No status ledger or SDD progress file was edited. All728 scope stays unchanged.

## What changed

Installed executable worker modes `compliance-export` and
`compliance-export-cleanup` in runtime configuration, database authority
selection and production composition. Execution requires the registered
`zasp_compliance_worker` authority; reconciliation/maintenance/deletion require
the distinct registered `zasp_compliance_cleanup` authority. SQS/audit-export
configuration is not a dependency, and mixed authority configuration fails.

Configuration uses `ZASP_COMPLIANCE_EXPORT_BUCKET`,
`ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER`,
`ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN`,
`ZASP_COMPLIANCE_EXPORT_ROLE_ARN` and
`ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE`, plus the existing worker
DSN/authority/ID/timing/region variables. The token path is the fixed EKS
service-account path. Leases are60seconds, batches1-10 and provider timeout1-30
seconds. SQL retains the persisted capacity/retry/retrieval policy.

The client constructor uses bounded TLS transport, explicit web-identity
credentials, pinned region/owner/KMS and one SDK attempt. Readiness checks the
granted candidate SQL function (which performs registered principal and release
readiness checks) and the exact configured STS role/session. It doesn't perform
synthetic bucket writes or pretend to inspect deployed IAM/lifecycle settings.

The processor claims scoped candidates, captures once, renders once and prepares
exact bytes before provider I/O. It reuses Task2's
`executeComplianceExportPackage` and `complianceLeaseHandle`.
Retries load the stored package; neither source updates nor a changed current
renderer regenerate it. SQL checks current source authority during preparation
and Finish. The current renewed lease reaches Finish.

A joined20-second heartbeat runs through bounded I/O. Lease loss cancels the
attempt. Cancellation or failure after Put records unknown storage with the same
lease where it remains usable; a stale worker cannot finalize or release quota.
The runtime closes admission, cancels borrowers, joins them, then closes idle
connections. If draining cannot finish, the database remains alive for the
retained borrowers. The shared serve loop now cancels its polling child when the
health listener fails, as well as on normal cancellation.

Initial rendering uses the existing sessioncontrol formatter. It consumes only
the frozen SQL snapshot and computes control freshness using snapshot_at,
required source categories, source timestamps and mapping age. Migration-seeded
configuration cannot establish a fresh category. It rejects overbounds and
unknown metadata fields. It doesn't copy policy bodies or raw prompts.

The formatter has optional typed source targets, bounded allowlisted metadata
and optional `snapshot_context` on ComplianceEvidence. Context contains the
captured organization/workspace/environment, mapping revision and snapshot time.
JSON, CSV and human formats retain these fields. Old records without them keep
their former output shape; the outer envelope remains
`{version,id,json,csv,human}`, version1, renderer
`compliance-envelope-v1`. Task4 must validate supported persisted envelopes
without comparing them against current rendering.

Read-only reconciliation uses a narrow read interface and exact-byte receipt
verification. It cannot PUT. Missing/denied HEAD is uncertainty, not absence.
A receipt verified after attempt exhaustion changes storage facts but preserves
the public failed state.

Cleanup uses a separate exact-version API. Generic artifactstore/S3 Delete is
unchanged and immutable. Cleanup issues a pinned DeleteObjectVersion request,
then a range-bounded exact-version GET and requires NoSuchVersion. It closes any
response body. Delete success alone, bodyless404, denial, timeout or a still
present/locked object cannot release capacity. A lost DELETE response can be
resolved by the following exact absence proof. SQL owns read-lease exclusion,
expiry, accounting release, package/snapshot pruning and deletion audit.

## REDs that caught behavior

Focused commands used the offline environment prefix below and selected only
the named tests. Recorded tool session IDs identify the observed runs.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -run '^TestComplianceRuntimeConfiguration$' -count=1
```

22543 failed: dedicated mode rejected. 37007 passed after installing configuration.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./sessioncontrol ./artifactstore/s3driver -run '^Test(ComplianceFormatterCapturedAttribution|ExportReadOnlyReconciliation|ExportCleanupRequiresVerifiedExactVersionAbsence)$' -count=1
```

48228 reported lost JSON attribution and missing new storage API symbols.
One incorrect fixture locator field was corrected. 97221 passed.
The absent-entrypoint failures are compilation evidence, not behavioral RED
proof. Renderer/candidate91994 and composition99659 likewise first failed on
their missing new API entrypoints; their substantive assertions run in the final
group.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./artifactstore/s3driver -run '^TestExportCleanupSDKExactVersionAbsence$' -count=1
```

40022 failed: deleted used [DELETE HEAD], lost-delete used [DELETE].
The controlled real SDK exposed the HEAD limitation identified by root.
14888 passed all cleanup cases after switching to exact GET verification,
including lost DELETE response and rejecting ambiguous bodyless404/denial.
Primary reference supplied by root:
[HeadObject documents generic errors without an error body](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -run '^TestComplianceRuntimeComposedLifecycle$' -count=1
```

67032 failed cancellation/revocation/close: unknown retry was missing.
A heartbeat canceled during normal join was being mistaken for lease loss.
48557 passed after distinguishing caller/join cancellation from renewal loss.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./sessioncontrol -run '^TestComplianceFormatterFrozenContext$' -count=1
```

47516 failed missing scope context. 12951 passed context and SDK fault checks.
The first SDK wrong-KMS fixture8312 used the configured key by mistake; changing
it to an actually different key fixed the test setup, not production behavior.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -run '^TestComplianceRuntimeListenerFailureJoinsPolling$' -count=1
```

61401 failed: listener failure left polling goroutine alive.
47116 passed after the shared loop acquired a canceled-on-return child context.

Focused registered process acceptance72077 passed in12.85seconds before the final
snapshot-context/stale-generation additions. It wasn't treated as final evidence.

## Final acceptance, frozen source

Commands ran from `services/platform`, except Docker and patch checks from the
worktree root. Final code has15 scoped files; each current hash matched the
AFTER identity when the report was written.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-compliance-task3-worker-final.test ./agentsec-worker
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 /opt/homebrew/bin/go test -c -o /private/tmp/zasp-compliance-task3-api-final.test ./apiserver
```

79862 and49243 both joined exit0. SHA256:

- Worker: `389021a8f68e9e9f802f4a0cdf95f53c3a1fbf99475e88f09e013eddd577de67`.
- The API binary is `e5a47034b8b6d3e3ac5c51bc3b2947e8ce23342c4161bb39a07e8033f0c56890`.

```sh
/usr/local/bin/docker run --rm --pull=never --name zasp-compliance-task3-final --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-compliance-task3-api-final.test,dst=/compliance.test,readonly --mount type=bind,src=/private/tmp/zasp-compliance-task3-worker-final.test,dst=/compliance-worker.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /compliance.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestCompliance' -test.v -test.timeout 180s
```

56831 joined exit0. Full output: [task-3-postgres-green.log](task-3-postgres-green.log).
The final polling acceptance passed in10.93seconds. Twelve fresh worker test
processes exercised production composition/serve/poll/adapter/formatter/store,
with the real SDK over controlled HTTP and a persistent object fixture:

SIGTERM during committed upload; byte-identical replay after source version
changes; denied cleanup retaining capacity; exact cleanup releasing capacity;
five unknown attempts; no-PUT reconciliation preserving public failure; source
revocation during upload; stale-generation Finish refusal. All children joined.

The same group reran current-source/scope/readiness tests, Task2's renderer-v2
restart proof across the original lease deadline, fresh authorization after
blocking waits, capture consistency, quota contention, read grants and cleanup
exclusion, and actual release56-to55 compatibility/downgrade checks. Twelve owned
PostgreSQL servers exited normally. The owner-inspection helper's top-level skip
is intentional; its parent launches it.

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker ./sessioncontrol ./artifactstore ./artifactstore/s3driver -run '^TestComplianceRuntime(Configuration|RendersFrozenSnapshot|CandidatesRejectUnsafeWire|ComposedLifecycle|ListenerFailureJoinsPolling)$|^TestCompliance(WorkerPersistedBytes|WorkerCleanupReceipt|WorkerHeartbeat|ReplayOutcomes|Export|Formatter)|^TestExport|^TestDriver|^TestNewRejects|^TestLoadWorkerRuntime|^TestServeWorkerRuntime|^TestRunWorkerPolling|^TestCloseWorkerRuntime' -count=1 -v
```

9236 joined exit0. Full output: [task-3-race-green.log](task-3-race-green.log).
Worker6.171s, formatter3.049s, artifactstore2.907s, S3 driver2.450s.
The existing shared serve tests passed: operational readiness/metrics, bounded
shutdown with an intentionally noncooperative processor, dependency drain
failure. The new listener-failure join test passed.

SDK cases include committed-write response loss, byte mismatch at an existing
key, pinned version/KMS/checksum/scope refusal, expected-owner denial, timeout,
missing object uncertainty, no-write reconciliation, exact-version deletion,
lost DELETE response, ambiguous404, lock/denial retention and absent version
refusal. These are controlled responses, not live AWS.

```sh
git apply --check --reverse .superpowers/sdd/2026-09-18-compliance-production-plan/task-3-scoped.patch
git diff --check -- services/platform/agentsec-worker/runtime_config.go services/platform/agentsec-worker/production_runtime.go services/platform/agentsec-worker/compliance_export_database.go services/platform/sessioncontrol/sessioncontrol.go
/usr/local/bin/docker ps --filter name=zasp-compliance-task3 --format '{{.Names}} {{.Status}}'
```

All exit0. No Task3 container remained. The broader actual diff-check command
also listed all newly added Task3 paths. Gofmt ran on every changed Go file.

No predecessor SQL or compiled release pins changed. Release55 up/down blobs
remain `7b70f6493e3e5a0b4fe06d6d6c1e033a85e1a192` /
`c3514105cdc9fcc1353dadd577d1b1eea06721a4`.
Release56 checksum remains
`cb01c3ac468a03b7f069b5f97ddc41c4fde9adf75171ba8b3c2dfd346857a50d`;
fingerprint remains
`4aeb4f9327a33d76ff828dae7bb9aa44fd33ecc864d9833df6775024ab81a5b4`.

## Review artifacts and limits

[task-3-scoped.patch](task-3-scoped.patch) contains only this task's changes,
built from captured BEFORE blobs and frozen AFTER blobs, not the inherited
working-tree diff. [task-3-blobs.json](task-3-blobs.json) lists all15 identities.
The patch is89,859bytes before its final newline normalization. No staging,
commit, push, reset, whole-tree patch or ledger change occurred.

I checked receipt/lease/cancellation paths, separate cleanup authority, context
ownership, optional attribution compatibility and source privacy during
self-review. Root's independent review is still required.

Live AWS IAM/KMS/versioning/Object Lock/lifecycle behavior is an external gate.
Operators must deploy distinct execution/cleanup identities and the24-hour
retrieval policy's corresponding object lifecycle/retention policy. The cleanup
role needs exact-version GET and DELETE permissions, plus read discovery for
reconciliation; execution must not receive deletion permission. Startup STS
identity checks do not prove effective IAM policies or installed retention.

No production endpoint, credentials or advisory data was used. The process
acceptance uses worker test executables invoking production runtime code with
registered SQL and controlled SDK transports; it does not claim a deployed
production binary or live provider acceptance. Host PostgreSQL, image pulls,
image builds and unrelated voxeval containers were not used or changed.

Task4's public grant/download lifecycle, Task5 UI/contracts/browser flow,
deployment, reference-load/scale and approved advisory evidence remain open.
Keep old persisted v1 packages readable without rerendering.
