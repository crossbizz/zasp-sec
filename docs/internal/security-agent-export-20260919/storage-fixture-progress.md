# Controlled storage fixture, 2026-09-19

The shared fixture is ready for integration review. It writes real package bytes to owned disk state and carries them through the real AWS SDK and product artifact-store driver, with every provider request intercepted locally. This is controlled storage evidence, not AWS acceptance.

Owner: `/root/public_export_storage_audit`. This packet creates only `services/platform/internal/exportfixture/store.go`, its test file and this report. No existing compliance fixture needed refactoring. Product runtime/API/SQL/pins/UI/scripts/ledgers/deployment files are unchanged by this owner. No container, external network request, commit, push or subagent ran.

I used the Superpowers TDD and verification-before-completion guidance. The storage, restart and browser audits supplied the composition limits. Interface choices were agreed with `/root/public_export_restart_audit` and `/root/public_export_browser_audit` before their consumers were locked.

## The frozen interface

Import `github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture` only from test fixtures. There is no production switch or fallback client.

```go
type Config struct {
    Directory, Bucket, Owner, KMSKey string
    MaximumBytes int64
}
func Create(Config) (*Store, error)
func Open(Config) (*Store, error)
func (*Store) Close() error
func (*Store) Remove() error
func (*Store) Objects(context.Context) ([]Object, error)
func (*Store) Requests(context.Context) ([]Request, error)
func (*Store) Transport(Options) http.RoundTripper

type Options struct {
    ReadOnly bool
    Before, After Hook
}
type Hook func(context.Context, Request) *Fault
type Fault struct {
    StatusCode int
    Code string
    Err error
    Body []byte
}
```

The worker starts first. It calls `Create` only when the exact owned directory is absent; later worker/API processes call `Open` with identical configuration. `Create` refuses an existing directory. `Close` closes its process-local handle and retains state. `Remove` belongs only to the creating handle, must run before that handle closes, and requires every borrower to have joined already. The parent harness can instead remove its own complete temporary root after all children join.

Agreed environment: `ZASP_SA_EXPORT_BROWSER_OBJECT` contains the canonical absolute directory `<owned-root>/export-store`, despite its historical OBJECT name. It is not a JSON filename. The parent should canonicalize its owned temporary root with realpath first; `/tmp` aliases aren't accepted as canonical parents.

Agreed config:

```text
Bucket=zasp-compliance-exports
Owner=123456789012
KMSKey=arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111
MaximumBytes=8388608
```

Use an actual `s3.Client` with `BaseEndpoint=https://controlled.invalid`, `UsePathStyle=true`, anonymous controlled credentials and `HTTPClient.Transport=store.Transport(options)`. No transport delegates to the network. API readers use `Options{ReadOnly:true}`. That permits only version-pinned GET/HEAD. Writer-side HEAD without a version is accepted for the existing driver's conditional-PUT discovery path; GET and DELETE always require a version.

Hooks run outside file locks, so an `After` PUT hook can block while another process inspects the already persisted bytes. The hook must honor its context. Return `Fault{Err: ...}` to lose a reply, or an HTTP status/code such as403/AccessDenied to inject a provider denial. A non-nil `Body` on an otherwise empty After fault replaces response bytes without changing the stored object. That supports corruption tests. The store records a durable `stored` event before calling After, including before a test deliberately signals its worker process.

## The disk contract

`state.json` is an atomically replaced snapshot:

```json
{"version":1,"objects":[{"key":"<full object key>","version_id":"fixture-<sha256>","body":"<base64 bytes>","headers":{"Content-Type":["application/json"]},"deleted":false}]}
```

The headers also retain the exact checksum, immutable version, KMS fields, size and supplied product metadata. JavaScript's byte oracle reads the base64 package and inspects its persisted envelope; it doesn't call a renderer to manufacture expected bytes.

Each key can create exactly one immutable version. Version IDs derive from the full key plus content bytes. Conditional retry returns412 and does not replace bytes or create another version, even after deletion. A deleted object retains only its key/version tombstone: `deleted:true`, `body:null`, `headers:null`. Its former bytes are no longer in the current snapshot. This isn't a secure-erasure claim about the host filesystem.

`requests.jsonl` holds sanitized records with fields `sequence`, `method`, `key`, `version_id`, `stage`, `status`, optional `code`, `size`, optional `sha256`. Sequence numbers describe disk log order. Hooks receive the operation facts, not an assigned log sequence. Stages are:

| Stage | Meaning |
| --- | --- |
| `before` | Validated request reached the controlled operation boundary. Count these for attempts. |
| `stored` | The operation and any durable mutation finished. PUT/status200 counts a new version; PUT/status412 is a conditional conflict. Reads also record this stage. |
| `response` | Reply or transport-failure observation. A killed process may have no response record after its durable stored record. |

Rejected host/path/pin/read-only requests fail before this log, so its attempt count covers admitted fixture requests, not every malformed request. No authorization headers, cookies, grant tokens or credential values are logged. State contains exported bytes and object metadata and must stay in the owned evidence directory.

Cross-process `flock` serializes mutations, snapshots and log appends; contexts bound lock waiting. Snapshot writes use exclusive temporary files, fsync, atomic rename and directory sync. The package uses descriptor-rooted file access, no-follow opens, regular-file/single-link checks and root identity checks. Traversal keys, symlink roots/files, mismatched configuration and unexpected cleanup entries are refused.

Limits are explicit: at most8MiB per object,64MiB retained body bytes,128 immutable identities,96MiB snapshot JSON,16KiB metadata per object and8MiB request log. Exceeding a bound fails closed. The current tests exercise per-object refusal; aggregate/log-cap saturation is not separate acceptance evidence.

## RED was reached, then GREEN

All Go commands below ran offline from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./internal/exportfixture -count=1 -v
```

The first run exited1 at the deliberately absent constructor. I classify that as setup RED, not upload proof. After adding disk ownership/opening with the transport still refusing all requests, the second run exited1 in5.897s: real AWS SDK PUT failed in the scope/restart and exact-delete cases; the persisted-write barrier wasn't reached; the concurrent writers failed. Two safety groups passed. This is the initial transport behavior RED.

After implementing the controlled transport, the focused race batch passed six top-level tests in2.145s. Expanded driver/fault/HEAD/process tests then passed11 groups in3.601s; these expanded tests characterized the implemented behavior, so I don't claim a separate RED for each.

A later test-first cleanup assertion caught a concrete miss:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./internal/exportfixture -run '^TestStoreDeleteErasesOnlyExactBytes$' -count=1 -v
```

Exit1, package0.522s: `deleted object bytes remain in snapshot`. DELETE had marked the version absent while retaining its body in the snapshot. The fix clears the deleted body's bytes and headers, preserving the immutable identity and the other tenant's object. No product cleanup code changed.

Final verification on the candidate below:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./internal/exportfixture -count=1 -v
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go vet ./internal/exportfixture
git diff --no-index --check /dev/null internal/exportfixture/store.go
git diff --no-index --check /dev/null internal/exportfixture/store_test.go
```

Race exit0, package3.563s,12 top-level PASS and zero SKIP. Both child processes in `TestStoreCrossProcess` started and joined: one created the version, the other received a conditional conflict. This is actual OS-process disk coordination; it doesn't prove product PostgreSQL recovery. Vet and both new-file whitespace checks exited0.

The12 test groups cover two successful scope-shaped keys, close/open byte continuity, conditional duplicate PUT, exact deletion, read-only refusal, pinned GET/HEAD/DELETE, pre/post-operation faults, cancelled barriers, lost PUT/DELETE replies, two concurrent handles, two competing child processes, path/host/deadline/size refusal, symlink/ownership safety and sibling-byte preservation. `TestStoreProductDriverAndExactCleanup` uses real `artifactstore.NewExport`, `s3driver.NewExport` and `NewExportCleanup`, including typed `NoSuchVersion` after a lost DELETE response. It checks two PUT attempts produced one stored version.

## Candidate bytes and limits

```text
c8413ae38d5fd4ed025c4f99472b6b0ea25ef984f4c44095a588e50fcb84a491  services/platform/internal/exportfixture/store.go
9cef0eed9729f2bc6b9725d2743a2d0269fb652e96adda2199b99ec09737dbe7  services/platform/internal/exportfixture/store_test.go
```

No product browser/registered SQL flow ran in this packet. Source authority, tenant policy, grant expiry/replay, final consumption, parent settlement and real UI saved-file evidence belong to the integration owners. The store distinguishes keys; it doesn't decide which principal may read them. AWS IAM, KMS encryption, legal holds, provider versioning and live credentials remain external gates. Arbitrary power-loss recovery during a partial log append is not modeled; the fault hooks give precise durable checkpoints for the required process interruptions.

Review the frozen fixture, then join the original run to its stored envelope and native browser downloads. Don't call this live storage.
