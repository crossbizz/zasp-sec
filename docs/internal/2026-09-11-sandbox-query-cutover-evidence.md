# Cutover components, not live authorization

The reviewed design and plan are in the same directory with the
`2026-09-11-sandbox-query-cutover` prefix. The executor is still being built.
Production release/admission provenance, a restricted live entry point and
actual rollout evidence remain required. No original task credit or push.

## Exact search visibility

`runtimeindex/opensearchdriver/session_visibility.go` adds
`SessionIndex.VerifyVisibleDocuments`. It accepts a bounded, nonempty collection
from one scope, expected to come from validated committed receipt/archive bytes.
It reads the fixed index mapping and marker, then uses a scoped IDs `_search`
request. Every full source, immutable version and document ID must match; totals
must be exact and all shards complete. Response ordering is not authority.
It issues no `_mget`, refresh, bulk write or initialization.

The initial test failed because the capability was absent (0.673s). Controlled
TLS tests then covered exact success, missing/duplicate/changed occurrences,
wrong index, version drift, partial/timed-out/terminated results, mapping/marker
failure and malformed response metadata. Input checks cover duplicate/mixed
scope IDs, empty/oversized requests, byte bounds and invalid or canceled contexts.

Independent review found cancellation at final response EOF could return success.
A deterministic regression reproduced that result (0.546s). The method now checks
the inherited context after reading and before returning success. Both final-read
cancellation and deadline tests require the typed canceled outcome. A race in the
test-only HTTP request log was also caught and fixed with a mutex.

Root focused races passed1.784s on the final test assertions. The full driver
package passed1.586s just before those assertions were strengthened; no product
change followed that full run. These are controlled transport/component tests,
not an actual OpenSearch deployment or a composed guarded cutover. Final
independent re-review accepted the method and repeated focused races in1.481s.
A subsequent full driver package run on the final source/tests passed1.836s.
The method is ready for cutover executor integration, not live authorization.

## Owned OpenSearch response contract

The existing `TestSandboxSessionIndexLocalOpenSearch` now invokes the verifier
against its real disposable OpenSearch3.8.0 instance. It rejects an unwritten
occurrence, accepts the exact sandbox occurrence after write/replay, accepts
historical v1 documents and a mixed historical/sandbox collection in target2,
and rejects an altered expected sandbox. Existing separate-schema, replay,
backfill, scoped query and foreign-tenant assertions remain intact.

Root run29862 passed without skips: test15.78s, Go package17.334s, exit0. The
existing dependency owner started a uniquely labelled loopback-only search
container and verified its identity before cleanup; cleanup completed. The image
was the repository-pinned OpenSearch3.8.0 digest. No production endpoint was used.
This closes the method's actual local provider-shape check. It does not establish
canonical PostgreSQL receipt capture, the transaction-held cutover fence, managed
IAM or a live Kubernetes transition. Independent test-extension review accepted
the assertion scope without rerunning a container.

## Executor state machine

The initial executor now verifies its release/observation boundaries, validates
real receipt/archive bytes with BuildDocuments, checks visibility, recaptures
under the adapter-owned fence and dispatches once. It preserves refused/applied/
indeterminate outcomes and separate cleanup confirmation. Its boundary adapters
are still fixtures, not implemented production provenance, PostgreSQL locking
or Kubernetes clients.

Root review found operation refusal was incorrectly conflated with unconfirmed
cleanup. `WithFence` now reports cleanup independently of callback errors. The
regression failed before the correction (0.523s); the implementer's suite then
passed1.490s. Root reread all three source/test files and independently repeated
the package races in1.485s. Further quality review precedes the actual database
adapter; this is not a composed cutover proof.

Task1 quality review subsequently approved that bounded state machine and
independently repeated package races in1.484s. The real PostgreSQL adapter is
now in development; no live adapter or end-to-end cutover claim follows.

## Sharing the observer deadline

The read-only compatibility observer now accepts an optional `deadlineUnixMs`.
It rejects invalid, expired or more-than30-second deadlines before reading the
cluster. Each sequential kubectl request gets at most5seconds and no more than
the remaining shared budget; results arriving after expiry are refused. Clock
rewinds cannot replenish the budget. Existing fixed release-profile checks stay
unchanged, and callers without this option retain the30-second observation cap.

Tests first reproduced ignored deadlines (2 failures), then reproduced acceptance
after a clock rewind. The combined observer/rollout tests passed43/43 in2.790s.
These tests use controlled query responses and real chart renders. They do not
prove live cluster identity or termination of a child ignoring signals. The Go
bridge must still enforce its own context and own subprocess cleanup. Independent
review accepted this deadline change and independently repeated the full observer
file:37 tests passed in1.801s, no skips.

## Backfill observation bridge

The read-only Node bridge now captures the API resourceVersion from the same
deployment-list response validated by the full11-consumer observer. It performs
no extra API identity read and no writes. Revalidation repeats the observer's
checks and refuses a changed opaque resourceVersion. Request/options fields are
closed; the caller must supply an absolute deadline. This is evidence, not
artifact provenance or deployment authority.

Initial three tests failed for the missing capability, then passed in2.334s.
Independent review found that parsing the captured response could overrun the
deadline after the inner observer's final check. A deterministic regression
failed with missing expected rejection (571ms). The final wrapper clock check
now refuses expiry and rewind. Combined bridge/observer tests passed41/41 in
2.814s, and independent review accepted the correction. Required release tests
now include this file: the workflow inclusion test failed first, then27 workflow
tests passed in1.25s and the complete release suite passed91/91 in16.770s.

The Go-owned subprocess bridge, composed database/provider/Kubernetes acceptance
and live provenance are still pending. No original microtask row advanced.

## Canonical PostgreSQL capture and fence

Task2 now has a dedicated configured migration-owner adapter. It requires the
complete compiled registry at50 and compiled50 readiness, then captures canonical
receipts with explicit LEFT JOIN refusal for missing project, complete or target
queue rows. The capture binds every scope/generation/digest/reference/version and
ordered occurrence ID. Its deterministic digest covers explicit scope fields;
row/byte bounds refuse overflow rather than authorize a prefix.

The rollback-only fence uses NOWAIT SHARE schema/metadata locks and self-conflicting
SHARE ROW EXCLUSIVE canonical receipt/target queue locks. Context deadlines and
server transaction/statement timeouts are bounded. Confirmed rollback/close or
exact PID+backend-start absence is required before reporting cleanup. No backend
termination, grants, migrations, CLI or provider writes were added.

Actual owned PostgreSQL18 races passed65.153s in
`/tmp/zasp-cutover-task2-full-postgres.log`. Root independently repeated all
Task2 PostgreSQL tests in62.486s. A further independent review ran database
subsets in21.576s and wire-bound/earlier-deadline units in3.369s. The tests cover
13 corrupt/incomplete authority cases with exact unchanged row snapshots, real
registered index-worker denial, registry/metadata drift, blocked new canonical
INSERT and post-cleanup progress, partial-lock cleanup, server-driven release
while the callback deliberately remains active, and cancellation/reacquisition.

RED controls include initial refusal of a nonempty valid capture4.621s, removal
of receipt/queue locks6.675s, and an isolated inner-JOIN overlay silently omitting
a missing queue row4.673s. A slow owner check also exposed a requested2s fence
whose server timer lasted3.009s. Merely changing a nonzero transaction timeout did
not shorten PostgreSQL's active timer. The adapter now disables/re-enables that
timer before acquiring application fence locks using the remaining budget.
The corrected timeout/cancellation tests passed11.733s. The timer behavior is
visible in PostgreSQL's `assign_transaction_timeout` implementation.

Independent review found that the contender callback's own error could conceal
an incorrectly acquired fence. The corrected test explicitly requires no callback
entry and runs that probe before queuing the writer; otherwise writer lock-queue
fairness can conceal a non-self-conflicting SHARE lock. An external SHARE-mode
overlay then failed4.525s in `/tmp/zasp-cutover-task2-contender-red.log`. Shared
source was never changed for that overlay.

The final two-scope fixture retains the same batch/event IDs in two tenants.
Removing either project or complete authority in one tenant cannot borrow the
other tenant's rows; capture and fenced capture refuse without mutating either
scope or target. Restoring the rows reproduces the exact ordered capture digest.
These assertions plus the corrected contender test passed11.912s in
`/tmp/zasp-cutover-task2-review-corrections-green.log`.

The independent reviewer inspected the final correction and both terminal logs
and approved the bounded Task2 specification and quality with no remaining
findings. This approval covers capture/fence, not the trusted loader or live gate.

The indexed/completed records are owner fixtures, not proof of real worker or
producer success. Large row/byte limits use a declared transport fixture rather
than10,001 producer batches. A server duration is not distributed absolute expiry;
downstream callbacks must honor their contexts, and arbitrary Go code cannot be
forced to return by the adapter. Production endpoint/CA/owner provenance remains
the trusted loader's responsibility. No live cutover or original-task completion
is inferred from this bounded database evidence.

The Node module now has a private stdin/stdout subprocess entry. A real child
process first reproduced an invalid-input success exit (RED104ms). It now bounds
stdin and stdout to4MiB, refuses arguments/malformed input with a fixed sanitized
error, and forwards only the read-only operation. A positive child-process test
uses actual renders and controlled kubectl responses; the real request parser,
observer and serialization run. All6 bridge tests passed in3.793s. This does not
prove cluster TLS or descendant termination; the Go process owner is still required.

Root independently reviewed the Kubernetes adapter source and TLS tests, with
focused races passing2.346s. Actual rendered templates exposed a Go/JavaScript
Unicode separator serialization mismatch; the corrected escape-aware encoder
preserves literal backslash sequences. Root reviewed the change and independently
passed both actual-render variants in2.367s. An isolated unconditional-PATCH
mutation failed the stale-version test, proving the refusal assertion catches an
applied stale write. These are controlled TLS fixtures, not a live cluster.

An independent second reviewer accepted the full Kubernetes slice and reran its
TLS/actual-render tests in3.315s with no skips. Task2 capture/fence quality review
also closed after a test-masking correction: the contender probe now happens
before the queued writer and explicitly requires its callback was never entered.
A SHARE-only overlay failed that isolated control in4.525s; unchanged production
locks plus same-ID cross-tenant project/complete refusal passed11.912s. The
reviewer's actual-PG subset passed21.576s and wire/deadline checks passed3.369s.

The later read-only query observation profile changes only the API selector to
target2 while retaining all11 schema50 consumer checks. Its actual query-render
test first failed for missing support (420ms), then passed while rejecting APIv1
and incomplete updated replicas. Combined observer/bridge tests passed44/44 in
4.327s; independent review repeated44/44 in4.457s, no skips. This later change
was not part of root full verification11329. Complete/failed rollout classification
and same-pinned Go observation remain pending.

## Read-only rollout outcomes

The separate rollout reconciler now distinguishes unknown transitions from an
observed applied patch. Exact applied UID/template/audit is required before
reporting applied. Current-generation, unambiguous ProgressDeadlineExceeded means
applied/failed. Missing/old replica evidence or a later mismatch remains
applied/pending, never refused. Complete requires the trusted full11 query
observation, followed by exact audit and opaque resourceVersion reconciliation.
Freshness and cancellation are checked again after that final read. There is no
PATCH, database call, provider write or cleanup claim in this API.

The refusing skeleton failed all four outcome cases (0.603s); the implementation
passed1.680s. Expanded TLS controls cover invalid identity, future/expired evidence,
resourceVersion/audit drift, stale or malformed/duplicate failure conditions,
final-read cancellation and evidence expiry during the final read. Initial wrong
audit/replacement UID/missing Deployment stays indeterminate with zero query
observer calls. Stable root artifact/rollout races passed3.579s; independent scoped
rollout review passed3.114s and approved the outcome checks. The query observer is
still a declared fixture in those tests. Actual Go full11 observation integration
and composed/live rollout are not established by this checkpoint.

A separate Go overlay removed only the final freshness check without changing
shared source. The final-expiry regression then failed in1.874s because expired
evidence was wrongly reported applied/complete. The overlay is
`/tmp/zasp-rollout-final-freshness.dVNIoL/overlay.json`; it is not used by normal
builds. The full release Node suite including the query profile also passed94/94
in14.510s with no skips, separately from the earlier full-root verification.

## Composed adapter review checkpoint

Root repeated the normal final-expiry rollout regression without the mutation
overlay: PASS2.431s. The immutable artifact adapter's actual SDK tests passed
1.759s in root verification and1.780s in independent review. Review approved the
Strong source-qualified sandbox-v2 projection/receipt/archive positive and the
corruption controls, including proof that non-slow failures did not merely expire
their contexts and archive corruption reached the intended HEAD operation.

Root's actual PostgreSQL composed cutover races passed35.068s with PostgreSQL18
on PATH. The implementer's complete cutover PostgreSQL suite passed96.799s.
These compose real database fencing, SDK artifact reads, exact HTTP search and
conditional TLS PATCH behavior; release provenance and full11 consumer observation
remain explicit fixtures. Independent review requested test-owned cancellation
and bounded goroutine joins before fixture teardown, plus a fresh invocation
against the already-query Deployment. Both corrections are now approved. The
cleanup regression first failed0.551s when release-only cleanup returned before
its owned task stopped. Cleanup now cancels the child context, releases barriers
and boundedly joins all started tasks before provider/admin/PostgreSQL teardown.
The writer returns errors to its parent test and task completion closes through
defer. A fresh already-query invocation refuses, preserves the original audit,
template and canonical evidence, and leaves the mutation count at one.

Final composed races74496 passed35.133s, no skips. The exact captured output is
`/tmp/zasp-cutover-composed-74496.log`. Independent correction review repeated
cleanup, success/fresh refusal, contention and post-dispatch pending controls in
14.364s, recorded in `/tmp/zasp-cutover-composed-independent.log`, and closed all
findings for this bounded composition. Root also reviewed the corrected source.
Both delayed overlap orders retain distinct audit identities and exactly one
accepted CAS from two invocation-local dispatches. An external overlay removing
only the three JSON Patch tests failed both orders9.648s; its raw RED is
`/tmp/zasp-cutover-cas-control.492lsf/red.log`. Shared source was untouched.

Fresh artifact races43465 passed1.794s, with actual Strong sandbox projection2
codec output, source binding and SDK HEAD/GET checks. Raw output is
`/tmp/zasp-cutover-artifact-43465.log`. The full prior PostgreSQL selection is
`/tmp/zasp-cutover-pg-33669.log` (96.799s, before final test-only corrections).
The concurrent internal-package observation RED is retained separately in
`/tmp/zasp-cutover-unit-48234.log`; it is not a full-package green result.

The composition derives receipt/archive bytes first, then inserts matching
fixture-owned canonical authority. It does not prove authenticated intake or
registered worker completion. Search and S3 responses are owned HTTP fixtures,
Kubernetes is an owned TLS server, and SDK provenance is a supplied trusted
construction input. Full11 Go observer composition and live release/admission
provenance remain pending. No original task credit or deployment authority follows.

The Go observation process adapter is still under implementation/review. Its
confirmed stdin-copy hang and post-cleanup evidence-publication failures received
test-first corrections, but process-exit watcher error cleanup and remaining
negative cases are not yet approved. A concurrent package run captured intermediate
cleanup RED tests; it is not a final stable package result. No original microtask
or production gate advances from these local adapter checkpoints.

Fresh root `npm run verify`65788 completed with exit0 under Node22.23.1:
197 UI files/1243 tests passed in25.61s, all94 release tests passed in14.745s,
typecheck/lint passed, and all five production build phases completed. Compiled
imports validated7 client/8 server chunks. The ledger checker still reports
728 rows:536 production-available,131 component-only,61 blocked/external,0 missing.
This root command does not run the new Go observation package's complete tests;
its stable focused verification and independent review are separate gates.

## Go observation base review closure

Independent review found a closed-protocol gap in Go's case-insensitive JSON
struct decoding. All42 alias/overwrite controls first failed1.212s. Exact
structural round-trip validation now rejects those keys while preserving opaque
image-map keys. Root's first Linux process run52502 also exposed a test-owned
listener-file publication race: it read the newly created empty file as port0.
Same-directory atomic rename and explicit port-range validation corrected that
fixture. These changes do not weaken process ownership or evidence checks.

Final Darwin/Node22 package races passed12.773s with no skips. Root's Linux run
62668 passed all five process/watcher tests and their subcases. It ran the static
linux/amd64 binary in Node22.23.1 at image digest
`sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`,
with init, no network, read-only filesystem and an unprivileged user. The Docker
host is arm64, so this is emulated Linux execution, not Linux race or full bridge
acceptance. Exact terminal output is `/tmp/zasp-cutover-observation-linux-62668.log`;
the prior failure excerpt is `/tmp/zasp-cutover-observation-linux-52502-red.log`.

The independent reviewer inspected the fix diff and terminal logs, approved both
specification compliance and quality, and closed the sole independent source
finding. The corrected implementer report is
`/tmp/zasp-cutover-observation-review-report.md`. No duplicate suite was required
for that scoped review. Query-mode Go observation and full11 TLS/PostgreSQL
composition are the next required steps; production provenance is still open.

## Query observation and release-source checkpoint

The query method is now independently approved for specification and quality.
It changes only the constructor-owned API target digest, keeps all non-API and
image pins, and bypasses backfill cache lookup, pruning, capacity and publication.
Actual Node full11 validation covers old replicas, changed workers/images,
freshness, cancellation and private-file cleanup. Query evidence cannot be reused
for backfill revalidation. Focused races passed7.997s and the full package passed
19.357s, no skips. A cache-publication overlay first failed1.084s with the expected
"query observation filled backfill cache" assertion. The scoped review used the
diff and exact terminal logs without rerunning unchanged tests.

Root's required `npm run production:release:gate`51383 completed with exit0 under
Node22. Its exact output is `/tmp/zasp-cutover-release-gate-51383.log`. This checks
release sources, source SBOM/licenses, container definitions, dependency and
resilience contracts. The script's secret scan targets committed HEAD, not the
entire unpublished worktree. It explicitly leaves built-image scan/signature,
remote CI, live providers and public DNS/TLS as release-environment gates.
The actual HTTPS/PostgreSQL/full11 observer composition now passes its tests;
independent specification and quality review approved it with no findings.

## Full11 composition verification

The real Go observer launches the Node bridge, whose controlled kubectl reads
the same owned HTTPS API as the conditional mutation client. Initial observation
and fenced revalidation require ten actual HTTPS reads across all eleven fixed
consumers. The success case applies one PATCH and preserves canonical evidence.
Old API pods, a missing target2 worker, changed API resourceVersion and changed
non-API templates refuse without a PATCH; fenced refusals confirm cleanup and
allow immediate fence reacquisition. Read-only query reconciliation stays pending
with old replicas, completes only after explicit test-owned controller progress,
and reports current-generation deadline failure without another PATCH.

The positive test first failed5.092s when the old fixture observer produced zero
HTTPS observation reads. Wiring the real observer passed6.607s. An isolated
query-bypass overlay failed5.694s because API-only evidence falsely completed the
old-replica rollout. Focused actual PostgreSQL races passed30.562s. Final91549
passed the complete sandboxcutover package21.570s, OpenSearch driver1.906s and
actual PostgreSQL TestSandboxCutover selection128.623s. The PostgreSQL selection
had no skips. Node release tests61378 passed94/94 without skips in16.124s.
Exact Go output: `/tmp/zasp-cutover-full11-go-91549.log`. The Node terminal suffix
and summary are `/tmp/zasp-cutover-full11-node-61378-terminal.log`; its truncated
initial tool chunk is not represented as a complete saved log.

Only the new observation PostgreSQL test and narrow existing fixture plumbing
changed. Release approval, completed canonical rows, expected pins and controller
advancement remain declared fixtures. This proves component composition, not
production artifact provenance, real admission, managed-provider IAM or live
rollout. Independent review inspected the complete two-file slice and terminal
RED/GREEN evidence, approved specification and quality with no findings, and
required no redundant suite rerun. No original microtask row advanced.

## Publication audit corrections

The plan audit found missing recorded evidence for the count-only visibility
mutation. An isolated external overlay preserved readiness, scoped read-only
query, shard/timeout and aggregate count checks but removed occurrence-level
comparison. Run57954 failed0.631s on missing, duplicate, source and version
controls; valid input still passed. Unmodified source passed the same narrow
selection48065 in1.396s. Source/test hashes matched before and after. Exact
commands and logs: `/tmp/zasp-visibility-count-only.1lmuXr/report.md`.

The coverage audit found that CI omitted the new runtimelineage package tests.
Root added its omission regression, which failed68105 in1.19s. Adding the package
to the existing CI precision command and workflow fixtures passed41609:28 tests
in1.00s. Actual runtimelineage package races41813 passed1.447s. This adds future
regression coverage; it does not change product behavior or original task credit.
The fresh ledger check remains728 rows,536/131/61. Main history was merged locally
as f5cfb2c3 with no file changes; no source increment has been committed or pushed.

Final root verification13612 completed with exit0 on the CI-corrected source:
197 UI files/1244 tests passed26.05s, all94 release tests passed15.278s without
skips, typecheck/lint and all five production build phases passed. The standalone
output was generated and compiled imports passed7 client/8 server chunks.
The ledger checker passed with the same728-row classification.

The final integration reviewer found no new blocking issue in cross-component
phase/CLI/readiness/factory/ingest/reconciliation/CI/cleanup wiring. Detailed SQL,
codecs and provider internals rely on their earlier scoped independent reviews;
this is not a new every-line review or live activation approval. The lineage CI
correction also passed independent scoped review. The shipping version helper
cannot classify this repository's unchanged package0.1.0 without a VERSION file;
main has never had that file. The existing version scheme is preserved rather
than treating that tool assumption as source drift.

Secret scan36354/34275 covered the full modified and untracked file bodies,
5.55MB, and reported12 generic-key findings. Independent metadata-only triage
confirmed nine existing tracked synthetic fixture detections and three new
loopback-checkpoint/database-stub tokens. No provisioned credential was found.
The staged scan then reported six detections across five exact locations: the
moved combined-proof signing/reveal fixtures, two checkpoint-client fixture tokens
and a precise-routing database-stub lease. These are reviewed false positives,
not a clean scan yet. Preserve exact historical-fingerprint exceptions, not a
blanket test-directory exclusion. All324 intended source/test/doc files are staged.
