# Task 4 implementation candidate

Status: DONE_WITH_CONCERNS — frozen for root-owned independent review, not release approval.
Base HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
No staging, commit, push, reset, root-ledger edit, image pull/build, live provider call, or original-scope deletion was performed.

## Known concern requiring review

The binding design (`docs/internal/2026-09-18-compliance-production-design.md:56`) requires missing/stale/fresh from current sources. SQL computes aggregate freshness across all matching sources, excluding migration-seeded configuration (`services/platform/migrations/sql/0056_production_compliance.up.sql:209`). The repository retains that enum (`services/platform/apiserver/compliance_repository.go:76`, strict decoder at 228).

The current HTTP translator does not preserve that aggregate enum. It loads only the first 100 evidence records for each control (`services/platform/apiserver/compliance_http.go:269`), then derives legacy `fresh_until` from their source timestamps (`compliancePublicControl` at 347). SQL pages are ordered by source kind/ID, not timestamp (0056 up.sql:208). Thus a fresh record after the first 100 can leave a control appearing stale; epoch fallback also cannot distinguish missing from stale in the direct legacy control shape. Evidence wrappers use per-record freshness at HTTP311, not aggregate control freshness. Seeded configuration is excluded from the derived deadline, but its record-level freshness still describes timestamp age and its metadata explicitly says unverified.

This is a concrete compatibility/semantic gap, not an accepted conservative approximation. Per root direction, this candidate is frozen without a speculative second implementation; independent review should decide the additive public contract needed to preserve SQL authority and add the >100-record regression. It must be resolved before claiming full Task4 compliance.

## Implemented surface

- Existing controls/evidence reads deliberately use the registered compliance handler when configured; five new routes provide typed evidence detail, export create/status, grant issue, and download. No duplicate legacy registration. Live controls remain direct controls, not export snapshot wrappers.
- Real mounted middleware enforces authenticated cookie, selected scope, origin/CSRF on mutations, and fresh authentication on creation. Handler and SQL enforce view + view_audit + view_compliance; SQL revalidates after waits. Actual SQL/session-auth HTTP lifecycle is exercised, not only injected identity.
- Export filters are canonicalized before hashing, control-only filters infer their framework, SQL generates the ID, status output excludes storage authority, and requested job identity is checked against the returned job.
- Grants use cryptographic 256-bit body-only tokens, persisted hashes, exact session/principal/scope/job/format binding, read leases and expiry bounded by job expiry. Public human is translated to SQL readable.
- Download verifies exact locator/version/media/size/SHA256 and immutable bytes, then validates the persisted v1 envelope. Optional context binds selected scope and mapping revision; old packages without context remain readable. No rerender equality or current-time rewrite. The final consume rechecks current authority and both clocks before any bytes.
- Response attachments have no-store, nosniff, exact safe filenames and bounded bytes. Shared client binary handling is restricted to the exact compliance download operation; ordinary JSON/error/auth behavior and immediate cancellation are regression-tested.
- Production storage uses pinned bucket/owner/KMS and a separate explicitly configured API reader role. The adapter cannot upload or delete. Readiness includes registered source authority; storage and owned transport cleanup are part of runtime composition. No ambient SDK credentials or provider URLs are exposed.
- Deferred Task1 conflict classification is fixed: only the exact SQL source_changed conflict maps to source_changed; unrelated serialization/deadlock errors remain distinct.
- OpenAPI and generated client are connected; the client was regenerated once, then checked for drift. Strict record/detail/job/grant decoders reject unsafe metadata, foreign detail scope, invalid targets, calendar overflow and malformed state. UI map marks the five new operations api_available, leaving UI wiring to Task5.

## Narrow release56 SQL delta

Root approved the `integrity_failure` grant operation required by the design. It runs existing current-auth/scope/job/token/format/lease checks, marks the grant used, and inserts a fixed audit event. It returns a successful bookkeeping result so the transaction commits; HTTP separately denies with a safe503. Replay cannot duplicate the audit. No raw token, provider reference/version, arbitrary metadata or diagnostics are audited.

The first audit implementation used outcome failed, which the existing administration audit table rejects. A direct diagnostic identified that constraint; the final operation uses rejected with action compliance.export.integrity_failed. The Docker lifecycle proves a durable audit exists after the denied HTTP response and verifies replay count and metadata exclusions.

Audit-write failure or request/deadline expiry never permits disclosure. The HTTP bookkeeping call is bounded and best effort; no durable audit is promised when authority is revoked, the lease expires, or the database cannot commit. This limitation is explicit for security review.

Release56 checksum: `af7be48e8b1444219414b4880cc7cfa4b40c6798222423a59e771e6af5955e41`.
Release56 catalog fingerprint: `794bd599bc37408e07b0c6238ad10052dbd40458ab24380481cc05caa0698cf9`.
Historical55 unchanged blobs: up `7b70f6493e3e5a0b4fe06d6d6c1e033a85e1a192`; down `c3514105cdc9fcc1353dadd577d1b1eea06721a4`.

## Verification

Full exact accepted commands, working directories, exit codes and captured outputs are in [task-4-verification.log.md](task-4-verification.log.md). All owned handles are terminal; no Task4 container or postgres/initdb process remained at the final targeted inventory.

| Check | Result |
| --- | --- |
| Owned cached, network-none Docker PostgreSQL batch43454 | Exit0; all selected TestCompliance source/job/grant/API/worker lifecycle tests pass. Child-process helper skip is intentional. |
| Explicit non-SQL race15047 | Exit0 across apiserver, agentsec-api, sessioncontrol, artifactstore, s3driver. Includes real runtime composition installed/disabled/unregistered. |
| Enumerated non-SQL names96067 | Exit0; no PostgreSQL/process fixture selected. Enumeration completed after the replacement race was started, not before. |
| Client/decoder batch69727 | Five files,48 tests pass, including existing shared-client, audit-export, administration regressions. |
| OpenAPI/generated/coverage Node batch63723 |44 tests pass. |
| TypeScript46822, scoped ESLint44538 | Both exit0. |
| OpenAPI lint and generated-client check | Both exit0. |
| Scoped patch reverse check | Exit0, against this frozen working tree. |

Focused TDD checkpoints observed before the final batch included:
source-conflict labeling RED→GREEN; missing-handler/config/decoder compile RED→GREEN; optional-body helper mismatch corrected from behavioral RED; durable audit denial RED→diagnosis→GREEN; attachment MIME and204 success rejection RED→GREEN; existing shared-client immediate-abort regression RED→GREEN; persisted empty-finding metadata and returned-job binding RED→GREEN; final calendar-overflow rejection RED→GREEN.
The retained diagnostic log includes full outputs for the broad rejected race, shared-client abort, initial contract expectation failures, and calendar-overflow RED. Earlier focused outputs are in the task conversation; they are not substituted for the final accepted evidence.

Production-composition startup diagnosis: missing test HOSTNAME failed `newConnectorWorkerOwner(os.Getenv("HOSTNAME"), rand.Reader)` at `services/platform/agentsec-api/production_runtime.go:330`, validated at478, during lifecycle-owner construction. It was not an initial config-validation failure. A test-only HOSTNAME fixed installed/disabled modes; no production bypass was added.

## Process deviation and limits

A broad local race selector85362 accidentally invoked owned host PostgreSQL fixtures despite the explicit no-host-PostgreSQL constraint. This is a process deviation, not accepted proof. It failed container-only worker paths and a timezone-sensitive source assertion. The subprocesses terminated and were joined; root was informed and independently checked no postgres/initdb remained. The complete output is preserved in [task-4-diagnostic-runs.log.md](task-4-diagnostic-runs.log.md), without relabeling it as a successful or sandboxed run. Replacement acceptance is the owned Docker SQL batch and the explicit non-SQL race. No unrelated containers were touched.

Controlled SDK transport tests are not live AWS/IAM/bucket-lifecycle acceptance. Deployment reader policy, bucket/KMS/lifecycle configuration and fresh approved advisory release evidence remain external gates. No full UI suite or live release gate was repeatedly run. Task5 UI/typed-selector work and root independent review remain separate gates.

## Frozen review artifacts

The 33-file scoped delta is built from captured BEFORE working-tree blobs, not an inherited whole-HEAD diff. New files have before:null. All AFTER blobs were written with git hash-object -w.

- [task-4-scoped.patch](task-4-scoped.patch): `f88d0dc65177c2e6a6b83e24a9c55e39860283a9`
- [task-4-blobs.json](task-4-blobs.json): `f86a7f44b450faafa50de7fba5e0fba4d66504bd`
- Accepted log: `1c9270a60af7cd545aaab90d7efef6a4a3a921fb`
- Diagnostic log: `c010baad91b0cd85ad46610e9d03ba55b88faea3`

Frozen Linux arm64 test binary SHA256:
`/private/tmp/zasp-compliance-task4-final.test`: `a52426c862232b22ddda4cd234eb56c9bc16a8d106e66d17de8ca5ec0a6fd1dd`.
`/private/tmp/zasp-compliance-task4-worker-final.test`: `488aae4f550d851d1963e907a0daddd089f7d2855ebe8efa149e73ad989e605f`.

Superpowers TDD guided the focused RED/GREEN work; feature-batched verification followed the user's explicit pacing instruction. The completion-verification check does not waive the aggregate-freshness concern above.

## Fix round 1 — Important findings and audit-write regression

Status: DONE_WITH_CONCERNS, frozen for independent re-review. This section supersedes the initial aggregate-freshness concern above for the fix1 candidate; the original candidate report and evidence are retained as historical records.

### Changes and coverage

1. SQL `listControls` now returns `fresh_until` computed from the maximum timestamp across all eligible matching sources, excluding migration-seeded configuration, using the mapping's maximum age. Missing categories retain the epoch sentinel. The already-authoritative SQL `freshness` is preserved by the dedicated HTTP `complianceLiveControl` projection (`services/platform/apiserver/compliance_http.go:349`). The 100-record evidence list remains a preview only and does not determine either aggregate value. The frozen `sessioncontrol.ComplianceControl` formatter and persisted envelope decoder were not changed.

   The real SQL/mounted HTTP regression (`compliance_http_postgres_test.go:21`) first failed with a stale2020 deadline despite a fresh101st source. It now passes that case, all-stale sources, no sources, and migration-seeded-only configuration, checking exact deadlines, aggregate enums, direct control shape and bounded preview lengths. Task3 exact-v1 persisted replay still passes with renderer-v2 calls=0.

2. Compliance attachments now default to4MiB independently of ordinary JSON's unchanged1MiB default (`apps/web/api/client.ts:82`). A caller's explicit smaller `maximumResponseBytes` remains effective, and the4MiB attachment ceiling cannot be raised by a larger caller setting. Tests cover1048577 bytes, exactly4194304 bytes,4194305 bytes, an explicit1MiB restriction, and unchanged ordinary JSON rejection above1MiB. The initial default-client RED reproduced response_too_large after a valid attachment.

3. Actual SQL audit-write failure is covered without a catalog or readiness bypass (`compliance_http_postgres_test.go:184`). The owned fixture holds a conflicting administration-audit relation lock; it observes the API backend waiting for RowExclusiveLock on exactly `zasp_admin_audit`, proving the integrity operation reached the INSERT after authority checks. It cancels that SQL operation while the HTTP request remains deliverable and the blocker stays held. Assertions prove safe503, no attachment or private body, no successful consume (`used_at` remains NULL), the durable read lease remains, and no additional audit row committed. The existing helper joins the HTTP/query goroutine and releases the owned transaction.

   An initial deferred-trigger injector was rejected as test evidence because the catalog change caused readiness rejection before the intended boundary. It was removed. The accepted test proves cancellation/write rollback, not a separately injected COMMIT-stage fault; no audit-failure production change was necessary because denial already failed closed.

### Connected legacy compatibility correction

Requiring the additive freshness field globally would break the unchanged legacy controls handler used when the new service is disabled. This was caught by a behavioral client/decoder RED, not papered over by changing old UI fixtures.

OpenAPI/generated types now make `freshness` additive and optional for the legacy boundary. Strict decoders validate its enum whenever the property is present (including rejecting null/undefined/unknown values); they do not synthesize a value when absent. Registered current-source HTTP responses always emit it, and the SQL tests explicitly require it. A disabled production-composition route regression proves old controls GET remains200 without synthetic freshness while the new detail route remains404; the real client plus decoder accepts that legacy shape unchanged. These compatibility results are not current-source evidence. Provisional edits to `SessionsComplianceView.test.tsx` and the old administration fixture were reverted byte-for-byte, so neither is in the fix delta.

### Final verification and pins

Full exact commands/results: [task-4-fix-1-verification.log.md](task-4-fix-1-verification.log.md).
Behavioral REDs, rejected injector and pin calibration: [task-4-fix-1-diagnostic-runs.log.md](task-4-fix-1-diagnostic-runs.log.md).

- Owned Docker full compliance batch15041: exit0, including source/job/quota/grant/API/worker runtime and frozen-byte replay. Focused SQL GREEN78679 also exit0.
- Explicit local apiserver race38413: exit0; names enumerated by84719 before launch.
- Explicit production-composition race51098: exit0; exact name enumerated by32573 before launch. No local PostgreSQL/process fixtures were selected.
- Final affected client/decoder/legacy-view batch79555:57 tests across6 files pass. The view fixture is unchanged; no full UI suite was run.
- Final contract4947:44 tests pass. TypeScript43981, scoped ESLint24052, OpenAPI lint and generated-client drift check: exit0.
- No live handles, owned Task4 fix1 containers, or postgres/initdb processes remained at freeze. No host PostgreSQL was launched in this round; no live providers, downloads, external advisory checks, staging, commits or root-ledger edits.

Release56 checksum: `1aed1a8b4e637d6fa77a2e993eaee3b58c4025e071b483b76487bb9e7a6fa606`.
Release56 fingerprint: `30358a1ceacbb18f0283e42353a06c88834d78927814dd8c6a9552a3a1d77a6f`.
Historical55 hashes were rechecked unchanged: up `7b70f6493e3e5a0b4fe06d6d6c1e033a85e1a192`; down `c3514105cdc9fcc1353dadd577d1b1eea06721a4`.

### Incremental frozen artifacts

The13-file fix delta uses captured BEFORE blobs from the reviewed candidate; the newly touched0056 SQL file was captured before modification. Original Task4 patch, manifest and logs retain their previous hashes.

- [task-4-fix-1-scoped.patch](task-4-fix-1-scoped.patch): `52964dde8d51506d7077a64040c550991d45e6c2`
- [task-4-fix-1-blobs.json](task-4-fix-1-blobs.json): `9acb1d62c5ec534767db47e2e43062986216c9f4`
- Accepted log: `39a9c7b75cf19a51ef1caee4b48d2f89bd5b2b88`
- Diagnostic log: `bbd2f886f97d78fc8239c415c415fa98b1077fd7`

Linux arm64 binary SHA256:
`/private/tmp/zasp-compliance-task4-fix1.test`: `5009418aa052f176c3c44129582e80d68ad36fa2ccd338cdef9fd5fc8ff69cd5`.
`/private/tmp/zasp-compliance-task4-fix1-worker.test`: `cfdb7894a0b45d9fa66934c6cf753f864056b2f5088472782b86c4614149c2c5`.

Self-review found no remaining fix1 Important gap. The two reviewer Minors—provider-read versus integrity-failure audit categorization and noisy composition telemetry—remain explicitly deferred by root. Independent re-review, Task5 UI, and live deployment/IAM/KMS/lifecycle/advisory gates remain open. TDD and review-reception skills guided the reproduced failures and the connected compatibility correction; no review finding was treated as a reason to weaken current-source authority.
