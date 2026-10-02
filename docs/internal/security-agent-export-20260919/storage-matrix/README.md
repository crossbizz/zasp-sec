# Storage handoff checks, September 19

## Review corrections

The initial version below had two coverage gaps. Its `other-session` cookie was unregistered, so 401 could occur before checking a grant's session binding. It also treated any `Store.Get` error after deletion as absence. That wasn't the production cleanup contract. The earlier run summaries are historical evidence, not proof of these corrected cases.

The revised refusal test persists another valid session for the same principal and scope. It proves that session can issue and consume its own grant, then checks that it cannot use the first session's unconsumed grant. Storage GET count stays unchanged during that refusal.

Cleanup now uses the real AWS SDK and `s3driver.ExportCleanup.DeleteExact`, with only HTTP transport controlled. Every request must carry the exact bucket, scoped key, version and expected owner; the verification GET must use `Range: bytes=0-0`. AccessDenied and generic 404 each return `ErrImmutable`, preserve the full retained job row and leave deletion audit count zero. Generic 404 follows a successful deletion, so even an actually absent local object cannot release accounting without typed proof. Only the SDK-decoded `NoSuchVersion` response permits the registered cleanup call. That call releases retention and writes exactly one deletion audit. Sibling/foreign-environment objects and rows remain intact.

Exact command output is retained in the `review-*.log` files. Each starts with its invocation and the SHA-256 of the test source used for that run. The session RED failed with 401 when the own-grant positive was first added; GREEN persisted the second session. The cleanup RED deliberately returned an untyped 404 in the expected-success branch, and `DeleteExact` refused it. GREEN supplied the typed `NoSuchVersion` XML response. No product code was mutated for either control.

These checks still don't execute the worker processor's retry/confirmation orchestration. The test coordinates registered SQL and the production deletion boundary; it cannot claim worker-process cleanup integration.

Corrected verification: the focused Refusals + ReadLeaseCleanup run passed in 35.171s. The full seven-test selector, including Lifecycle, Cancellation and Release, passed in 147.230s with no skips. See [the complete full-run output](review-full-green.log) and [all source/log hashes](SHA256SUMS). The test source remained unchanged between those two runs:

```text
e6ee690af2b9f7c717c2ee747a14c59597f13f80eaf45c71b36ac4bd3506901c
```

From the worktree root, verify the source and captured logs with:

```sh
shasum -a 256 -c docs/internal/security-agent-export-20260919/storage-matrix/SHA256SUMS
```

This is local integration evidence. The new file is `services/platform/apiserver/security_agent_export_storage_download_postgres_test.go`. No product SQL, release pin, ledger, worker script or existing test was changed for this matrix.

The fixture installs release58, registers concrete API/executor/cleanup logins and calls the real dispatch, capture, prepare and finish functions. It completes three distinct packages: one target, a sibling run in the same environment, and another run in a different environment. Each package goes through `artifactstore.Store` with its own immutable version. The HTTP requests use the mounted production middleware, repository, handler and artifact reader.

The download provider driver is a local map. Cleanup uses the production SDK deletion boundary over a controlled HTTP transport sharing that map. Authentication returns a fixture identity, while the grant SQL checks the real persisted session, membership and scope. Plans and package rendering are fixture-owned. Keep those limits attached to this evidence.

## What was missing

`security_agent_export_download_test.go` already checks original formats, manifest/run/selection binding, package schema, hashes, immutable versions, content limits and cancellation. Its inputs are component fixtures.

`security_agent_export_http_test.go` covers public request validation and consume-before-response ordering with a database double. `TestSecurityAgentExportLifecyclePostgres` already checks real grant SQL, revocation after database row-lock waits and single-use consume. `TestComplianceExportsDurablePostgres` checks an ordinary compliance export's live-read cleanup gate.

The new groups connect those boundaries. They don't duplicate every malformed manifest field.

| Group | Observable result |
| --- | --- |
| `StorageDownloadRefusals` | Exact stored JSON, CSV and human bytes, attachment/media/no-store/nosniff headers. Wrong format, sibling run, foreign environment, session, CSRF and expired grant disclose no content, reach no storage GET and leave the grant unchanged. |
| `StorageDownloadGrantRaces` | Two independent API connections reuse one grant while the first GET is paused. Exactly one storage GET and one successful byte response. Membership/scope revocation at that same barrier makes final consume refuse and disclose no package bytes. |
| `StorageDownloadCorruption` | Corrupt bytes, wrong immutable version, swapped sibling selection and malformed package all return 503 without content. One used grant, cleared read lease and one integrity audit; replay adds neither I/O nor another audit. Semantic attacks have matching outer hashes in both storage and the recorded receipt. |
| `StorageDownloadReadLeaseCleanup` | A real HTTP request pauses inside storage with a persisted live read lease. Registered cleanup cannot claim it. A read deadline set to the database clock, or successful HTTP consume, permits cleanup. Production `DeleteExact` refuses denial/generic 404 and accepts only SDK-decoded `NoSuchVersion`; registered confirmation then clears target retention while sibling/foreign-environment objects and job state stay intact. |

The expiry case puts the timestamp at `clock_timestamp()` and makes the next database call after that point. It is an expired-boundary test, not a frozen-clock proof of mathematical equality inside the claim statement.

## Initial runs, before review

All commands run from `services/platform`, with `GOPROXY=off GOSUMDB=off` and `-count=1`.

Initial setup exposed two fixture mistakes: the job column is `generation`, and sibling dispatches need distinct audit IDs. Both were corrected in the new file. Those failures weren't behavioral RED evidence.

The first connected refusal run passed in 12.719s. The remaining three groups passed in 93.557s. After connecting cleanup's lease to a paused HTTP GET, its two cases passed again in 22.494s.

An owned-file-only negative control temporarily made the provider driver return `matrix-negative-control-wrong-version` for every read. The positive stored JSON assertion failed with HTTP 503 (`provider_unavailable`) in 10.940s. The control was then removed. No product implementation was mutated. This checks the positive oracle's sensitivity; it is not a claim that each production guard received a mutation test.

Observed release pin:

```text
checksum:    5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985
fingerprint: 8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f
```

Initial full verification command:

```sh
GOPROXY=off GOSUMDB=off go test ./apiserver \
  -run '^TestSecurityAgentExport(StorageDownload(Refusals|GrantRaces|Corruption|ReadLeaseCleanup)|Lifecycle|Cancellation|Release)Postgres$' \
  -count=1 -v
```

Initial full result: exit 0, seven top-level tests passed, no skips. Selected output:

```text
--- PASS: TestSecurityAgentExportLifecyclePostgres (10.80s)
--- PASS: TestSecurityAgentExportCancellationPostgres (14.91s)
--- PASS: TestSecurityAgentExportReleasePostgres (7.96s)
--- PASS: TestSecurityAgentExportStorageDownloadRefusalsPostgres (11.86s)
--- PASS: TestSecurityAgentExportStorageDownloadGrantRacesPostgres (34.21s)
--- PASS: TestSecurityAgentExportStorageDownloadCorruptionPostgres (44.72s)
--- PASS: TestSecurityAgentExportStorageDownloadReadLeaseCleanupPostgres (21.13s)
PASS
ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 146.238s
```

`gofmt -l` and `git diff --no-index --check /dev/null` for the new test file produced no formatting or whitespace diagnostics. The no-index comparison reports a new-file difference.

After the full run, cleanup gained an explicit comparison of the registered claim's organization, workspace, environment, export, reference, version and lane against the target. Both cleanup cases passed again (exit 0, 23.174s). The wrong-version fixture was also narrowed to a syntactically valid but different version ID so it exercises immutable locator mismatch without relying on invalid characters. Its focused rerun passed (exit 0, 12.001s):

```sh
GOPROXY=off GOSUMDB=off go test ./apiserver \
  -run '^TestSecurityAgentExportStorageDownloadReadLeaseCleanupPostgres$' -count=1 -v
GOPROXY=off GOSUMDB=off go test ./apiserver \
  -run '^TestSecurityAgentExportStorageDownloadCorruptionPostgres$/^wrong_version$' -count=1 -v
```

An optional concurrent `-race` attempt failed in `initdb`, before exercising any case: `shmget` reported exhausted shared-memory IDs. The ordinary suite finished successfully. No existing PostgreSQL process or shared-memory segment was changed. The serialized retry passed:

```sh
GOPROXY=off GOSUMDB=off go test -race ./apiserver \
  -run '^TestSecurityAgentExportStorageDownloadGrantRacesPostgres$' -count=1 -v
```

```text
--- PASS: TestSecurityAgentExportStorageDownloadGrantRacesPostgres (35.51s)
    --- PASS: TestSecurityAgentExportStorageDownloadGrantRacesPostgres/same_grant (12.15s)
    --- PASS: TestSecurityAgentExportStorageDownloadGrantRacesPostgres/membership_revoked (11.62s)
    --- PASS: TestSecurityAgentExportStorageDownloadGrantRacesPostgres/scope_revoked (11.74s)
PASS
ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 37.532s
```

## Still outside this proof

No public planner admission, separate upload/cleanup worker process, live S3 provider, production session authentication or second organization is exercised here. The foreign object uses a different environment in the same organization. Cleanup coordinates registered SQL and the production artifact store from the test; it does not launch the cleanup worker.

The existing worker-process test has its own owned binary requirement (`/compliance-worker.test`). It is outside this file's final local selector. A full two-organization, real-renderer, process-connected proof needs that worker ownership extended separately.
