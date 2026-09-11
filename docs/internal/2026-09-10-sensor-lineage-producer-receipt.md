# Producer-side receipt admission

This is verified component progress, not daemon activation or permission to
delete source history. M3-46, M3-47 and M7-07 remain open. The 728-task ledger
still records 535 production-available, 132 component-only and 61 external gates.

## The boundary now enforced

`sensoradapter.VerifyConsumptionSource` reads an admitted source without a
consumer checkpoint, normalizer, credential or transport. It compares the exact
trusted source contract and configured HTTPS ingest destination, device/inode,
bounded progress and accounting shape, then rereads the full consumed prefix and
recomputes sequence, record count, byte count and digest chain. It checks context
around reads and at the end. A closed or changed source fails. Integer limits
are applied before arithmetic; the consumer checkpoint now shares that bounded
progress validator.

The caller must supply trusted installation identity and destination. These
values cannot come from the receipt. Submitted/dropped totals remain trusted
consumer accounting; consistent totals do not independently prove remote delivery
or replay normalization. The verifier has no service credentials and makes no
claim of cryptographic service attestation.

`lineageReceiptReader` is a separate read-only type. It cannot call the consumer
writer's lock, publication or scratch-recovery methods. It pins an owned 0750
directory under a protected parent and checks a bounded closed filename set.
The production constructor requires a Linux root producer and a configured
nonzero consumer UID. Fixture construction supports the host test UID explicitly.
Unknown, oversized, wrongly owned or linked entries fail closed.

`lineageSpool.VerifyAcknowledgment` holds the local producer mutex and existing
producer ownership lock, then the receipt-reader lifetime mutex, throughout
verification. It rejects the active target generation, while allowing a different
generation to be active. A source reader must resolve to the same parent inode as
the held producer spool, with the exact expected source contract. Receipt and
source directories must differ. A moved generation in a replacement spool cannot
be adopted merely because its source inode and bytes still match.

The method reads only the expected generation's bounded canonical receipt and
keeps its file descriptor open. Filename/source, manifest hash, exact complete
seal, seal hash, physical generation, destination and reread prefix must agree.
It rechecks the held/named receipt identity, exact bytes, source manifest and seal,
all lifetimes and context before returning. A missing receipt returns `found=false`;
invalid evidence returns an error. Neither case triggers cleanup or repair.

The returned value is readiness evidence. It is not a reusable deletion capability.
Future reclamation must repeat validation while holding its mutation ownership
lock and use a crash-safe protocol. Controlled producer/consumer permissions are
still required. Filesystem reads are bounded by size/count but have no hard I/O
deadline. Device/inode changes fail closed; this does not implement volume-remount
or cross-host restoration of old receipts.

## Tests and review

Superpowers is not installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflows are the disclosed
fallback. No installed skill run is claimed.

The independent prefix and producer admission tests first failed at runtime
against fail-closed stubs:
`/tmp/zasp-lineage-receipt-source-red.log` and
`/tmp/zasp-lineage-receipt-admission-red.log`.
The actual HTTPS/PostgreSQL producer-verification assertion also failed before its
test-process implementation: `/tmp/zasp-lineage-receipt-installed-red.log`.

Tests cover an empty sealed generation, exact source consumption with the consumer
checkpoint removed, missing versus invalid receipts, altered binding/counters,
canonical JSON, duplicate/unknown fields, modes, links, owners, source corruption,
missing seals, active target rejection, receipt/manifest replacement during reads,
late cancellation and concurrent Close. Input integer extremes, unexpected reader
panic, cancellation during reads and a source closed during verification reject.
No test grants remote-delivery proof from submitted/dropped accounting.

The compiled sensor child now verifies its consumer receipt in a separate producer
process after actual local TLS ingestion, PostgreSQL acceptance, response loss,
credential rotation and restart. The token file is physically moved away for
producer verification. That path never opens the token, CA, client or consumer
cursor; zero token reads and requests are recorded. Receipt bytes, immutable source,
original authority and the two batches/ten stage rows/two outbox rows stay intact.
Provider identity and artifact storage remain fixtures, not live Tetragon or S3.

Final full adapter races passed in 12.233 seconds:
`/tmp/zasp-lineage-receipt-final-adapter.log`.
Full sensor-agent races passed in 32.888 seconds:
`/tmp/zasp-lineage-receipt-final-agent.log`.
Focused receipt/admission races passed three repetitions in 14.814 seconds:
`/tmp/zasp-lineage-receipt-focused-final.log`.
The containing actual HTTPS/PostgreSQL test and artifact regression passed in
24.857 seconds, including the receipt scenario in 17.01 seconds:
`/tmp/zasp-lineage-receipt-installed-green.log`.

Independent review found no concrete blocker in the bounded admission component.
The receipt descriptor and final identity/byte checks, lock order, absence/error
distinction and integer bounds were reviewed. Review grants no reclamation,
activation or shipping approval.

Linux receipt/ACK cases passed three repetitions as UID/GID 65532 with no
capabilities. The root fixture used only SETUID/SETGID/CHOWN to launch a real
non-root consumer and construct the ownership tests. The child still cannot write
producer files. After it exits, the root producer's production reader admits the
configured UID65532 receipt against root-owned source, then rejects a receipt
changed to a foreign owner without deleting it. UID0 cannot be the consumer issuer.

The first root fixture run failed only during cleanup: without DAC override,
root could not remove the consumer-owned output directory's files. The fixture
now restores that one temporary directory's owner after all assertions. The
unchanged restricted permission profile then passed three repetitions. An initial
mistyped image digest also failed before any container or test started. Neither
failed attempt is passing evidence.

All proof containers used 256 MiB/no-swap limits, 0.5 CPU, read-only root, no
network, 128 MiB noexec/nosuid temporary storage, `GOMEMLIMIT=128MiB` and no
healthcheck. Successful runs exited zero without OOM. All three owned exited
containers were inspected and removed; their logs and binaries remain. Inspection
records are `/tmp/zasp-lineage-receipt-linux-first-inspection.log` and
`/tmp/zasp-lineage-receipt-linux-final-inspection.log`. These are small-fixture
permission/component tests, not full-daemon or fleet-throughput evidence.
Logs: `/tmp/zasp-lineage-receipt-linux.log`,
`/tmp/zasp-lineage-receipt-linux-permissions.log` (initial cleanup failure), and
`/tmp/zasp-lineage-receipt-linux-permissions-final.log`.
Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final Linux test binary:
`/tmp/zasp-lineage-receipt-linux.0jJhei/sensor-agent-reviewed.test`, SHA-256
`fad8f4f23fdc526eebf28aa834ef332677c33958b9ad5723e4b536b1629f1060`.
The earlier unprivileged run used the same product code before the root fixture
cleanup change: `sensor-agent.test`, SHA-256
`f7bc8476bf673f3ff60bb8d13182efe422e347603bd1fec352715a69ce43d4a0`.
Production Linux binary: `/tmp/zasp-lineage-receipt-linux.0jJhei/sensor-agent`,
SHA-256 `bbaca2a328ed78a2f149b974861c7010a9ff290e86352b45b05463e057d9b15b`.

## UI/build verification and remaining work

The complete root `npm run verify` passed using pinned Node 22.23.1. It includes
all 196 UI test files and 1,180 tests, typecheck, lint, API contracts, tenancy/RLS
checks, release-contract tests, the actual production build and compiled import
checks. The compiled graph has seven client chunks and eight server chunks.
Log: `/tmp/zasp-lineage-receipt-root-verify.log`. This is current local build/test
evidence, not composed Chrome, whole-branch Go coverage or deployed production.
The final ledger validator and all 27 ledger tests passed after the documentation
update, as did `git diff --check`.

Follow-on bounded reclamation is recorded in
`docs/internal/2026-09-11-sensor-lineage-reclamation.md`. It doesn't activate the daemon.

Next: consumer receipt/checkpoint retirement, completion-record collection and rotation,
lifecycle, daemon/deployment wiring and resource behavior, pinned live source
compatibility, original sandbox/cgroup/process correlation and source-to-browser
acceptance. Remaining acceptance/replay gates, composed Chrome and whole-branch
review still precede a verified push to main. No task credit or push is claimed.
