# Task4 final connected fix

Both deferred Minors are fixed locally. Independent controller review remains pending; publication and external gates are unchanged.

I used the receiving-review, systematic-debugging, TDD and verification skills. The existing design and preflight settle the error distinction: only a successfully returned object or persisted envelope that violates its pinned contract is an integrity rejection. A provider error, interrupted body read, timeout or cancellation does not prove corruption. No new authority or design expansion was needed.

## What changed

The safe `artifactstore.ErrIntegrity` category survives the real s3driver and Store read layers. Each layer still matches its existing `ErrGet` with `errors.Is`; provider text never enters the returned category. Context cancellation/deadline stays recognizable in the storage layers. Compliance mismatch errors retain `errors.Is(ErrRepositoryUnavailable)` and the integrity marker. The public boundary always emits its existing generic denial.

Only integrity rejection invokes durable `integrity_failure`. A provider failure leaves the already-acquired read lease untouched, without a corruption audit, terminal consume or attachment. No failure extends the deadline or grants a retry. A verified download still passes the existing SQL consume/current-authorization check before any bytes leave.

Composition now has a private writer parameter below the existing storage factory wrappers. Their signatures and defaults are unchanged: production still supplies `os.Stdout`, and there is no environment switch. The compliance fixture uses a mutex-protected capture, checks that spans and HTTP records arrive, and prints captured diagnostics only if its subtest fails.

Two directly connected details are included: the fixture grant response now matches SQL's terminal `integrity_failure` result; an S3 Get body returned alongside an error/cancel is closed before denial. No SQL, formatter, OpenAPI, generated client or UI source changed.

## Evidence, with boundaries

| Requirement | Fresh evidence |
| --- | --- |
| Failure category through actual driver, Store and mounted HTTP | `TestComplianceReadFailureClassification`: 11 cases across three layers. HEAD/GET/body outage, cancellation, deadline, wrong version, foreign metadata, checksum, body mismatch, invalid envelope, valid flow. Exact read/audit/consume operation sequence; no attachment or diagnostic disclosure. |
| Durable state, real session middleware and SQL | `TestComplianceHTTPPostgresReadClassification`: same 11 cases with registered database authority. Captures read deadline before provider access. Checks used_at, unchanged/cleared deadline, safe audit metadata/count and replay denial. |
| Current auth, tenant and post-wait behavior | Existing `TestComplianceGrantFreshAfterWaitPostgres`, mounted HTTP denials and exact-scope Store/driver tests pass. |
| Integrity audit write failure | Existing `TestComplianceHTTPPostgresGrantLifecycle` still cancels the actual blocked audit INSERT, denies bytes and proves rollback/no consume. It also covers expiry/revocation and audit replay. |
| Historical persisted bytes | Existing persisted attribution/old-envelope tests and `TestComplianceWorkerReplayPostgres` pass. Worker replay uses original v1 package bytes; renderer-v2 calls remain zero. |
| Runtime durability | `TestComplianceRuntimePollingPostgres` passes interruption/resume, cleanup, unknown/reconcile, revocation and lease loss with joined children. |
| Captured telemetry and unchanged factory wiring | `TestComplianceAPIProductionComposition` installed/disabled/unregistered cases and `TestComplianceStorageFactoryBoundary` pass under race. Operational telemetry/deadline cases also pass. |

Focused behavioral RED, handle 47883, exited 1 for the expected lost categories and false audits. The preceding missing-category compile RED 61493 and missing-telemetry-seam compile RED 60917 are preserved separately in the RED log.

Focused GREEN 99008 exited 0. Its first capture was output-limited, so that diagnostic log is not the full acceptance record. Every focused case ran again in the complete grouped log:

- Host race 66530: exit 0, 61 explicitly enumerated non-SQL/non-process test names across artifactstore, s3driver, apiserver and agentsec-api. Full enumeration preceded execution.
- Cached owned Docker 99466: exit 0, five top-level SQL tests, including the new 11-case classification test. All PostgreSQL and worker children joined with normal exits. The named container was removed on completion.
- Linux/arm64 API build 5284 and worker build 52265: both exit 0, offline.

Exact commands and complete grouped outputs are in `task-4-final-fix-verification.log.md`; REDs and pre-race enumeration have their own logs. The new tests control the SDK client boundary; existing grouped SDK transport/replay tests cover the actual SDK without live AWS. This is not live-provider proof.

## Source freeze

Ten source/test paths only, captured in `task-4-final-fix-blobs.json`. Every existing path has a current-worktree BEFORE blob; the three new tests have null BEFORE. The 671-line incremental patch uses those blobs and preserves inherited changes, including Task5's factory wrappers. HEAD remains `8733b16f8d939d38a8157dd2519e57fc6f630542`. No staging, commit or push.

Reused UI evidence is the independently reviewed Task5 fix1 run: 2096 UI tests and composed browser native JSON/CSV/human downloads, restarts and session continuity. I checked all 25 combined Task5/fix1 manifest paths against their reviewed AFTER identities. Twenty-four are unchanged; only `production_runtime.go` differs in this batch and has fresh composition/operational race coverage. Exact mapping is in `task-4-final-fix-reused-identities.json`. I did not rerun UI/build/browser, and do not claim the old composed-browser run executed this final backend revision. Root owns fresh publication checks.

Release55 SQL blobs remain `7b70f6493e3e5a0b4fe06d6d6c1e033a85e1a192` (up) and `c3514105cdc9fcc1353dadd577d1b1eea06721a4` (down). Release56 remains unchanged: up `5cef6f19e09e6c882c6dc1237b56bf48bb700261`, down `4f849ace1c181e4c57904486bdded410119dcc2a`; fingerprint `30358a1ceacbb18f0283e42353a06c88834d78927814dd8c6a9552a3a1d77a6f`. No migration/pin recalibration.

I read the incremental production diff and all new tests after the grouped run. No remaining finding in this two-Minor scope. The original 728-task scope, release/advisory gate and external storage/operator proof are untouched. Review the frozen delta next.
