# Acknowledged source cleanup, with retained completion evidence

This is component progress. M3-46, M3-47 and M7-07 remain open; none of the
728 original tasks receives new production credit. The daemon isn't activated.

`lineageSpool.ReclaimAcknowledged` holds the producer mutex and filesystem lock.
It rejects an active target and repeats the configured-issuer receipt admission
before writing intent. The record binds trusted source, ingest destination,
consumer UID, exact ACK, spool device/inode and the sealed generation's complete
file inventory. Every file has a bounded size, digest and physical identity.
All remaining files are opened and checked before any deletion.

Intent publication uses an owned scratch file, file sync, atomic rename and
parent sync. Only a matching interrupted-publication prefix can be recovered.
The generation then moves to its exact tombstone name. Each unlink checks the
pinned marker, directory and file again. Unexpected names, links, changed bytes,
ownership, modes or physical identities stop cleanup. An original directory with
missing files isn't accepted as an interrupted deletion. A tombstone without
intent isn't adopted. Copying an intent and its original source inode into a
different spool fails the spool-parent binding.

Directory removal follows file deletion and directory sync. Parent sync establishes
source absence before the completion record replaces intent. Retry re-establishes
the sync barriers, including when no source directory remains. A protected intent
can resume without consumer files; source absence alone cannot authorize cleanup.

Completion records remain root-owned and readable, with a maximum of eight.
They prevent generation-ID reuse and preserve evidence for consumer retirement.
Source slots are reusable, but a ninth completion currently stops without deletion.
This does not yet support indefinite operation. Consumer ACK/checkpoint retirement,
completion-record collection, orphan/unsealed recovery and automatic rotation remain.

## Tests that actually ran

Superpowers isn't installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflows are the disclosed
fallback. No installed-plugin pass is claimed.

The fail-closed stub first failed the reclamation assertions:
`/tmp/zasp-lineage-reclaim-red.log`. Tests then covered empty and nonempty genuine
ACKs, all 128 chunks, quota, exact source and issuer/destination matching, active
generation denial, altered resumes and copied intents.

Cancellation and actual child-process exit/restart cover nine boundaries: intent
scratch, intent publication, source rename, first file deletion, seal deletion,
last file deletion, directory removal, completion scratch and completion publication.
Linux O_PATH descriptors cause real directory-sync failures at intent, rename,
directory removal and completion. Recovery succeeds after reopening valid handles.
These tests establish checked filesystem ordering and process-crash behavior;
they don't simulate power loss or prove every storage device's durability.

Full sensor-agent races passed in 40.255 seconds:
`/tmp/zasp-lineage-reclaim-final-agent.log`. After the last test-only copied-intent
case, final focused races passed in 14.126 seconds:
`/tmp/zasp-lineage-reclaim-focused-final.log`.

The actual local TLS/PostgreSQL composition first failed before the compiled test
child implemented cleanup, then passed in 28.913 seconds (scenario 18.94 seconds).
Logs: `/tmp/zasp-lineage-reclaim-installed-red.log` and
`/tmp/zasp-lineage-reclaim-installed-green.log`. Token and checkpoint are physically
moved away during producer reclamation. Retry also works with the ACK directory
unavailable. The child performs zero token reads or HTTP requests; the existing
three-request/two-artifact trace and ACK bytes remain unchanged. Earlier assertions
in the same scenario verify two database batches, ten stage rows and two outbox
rows after response loss and credential rotation. Source identity and artifact
storage remain fixtures. This isn't live Tetragon, S3 or browser acceptance.

Linux tests passed three repetitions as UID/GID 65532 without capabilities.
A second fixture used root with only SETUID, SETGID and CHOWN, launched the actual
non-root consumer, verified its ACK as root and reclaimed root-owned source while
leaving consumer-owned ACK bytes and ownership intact. Both runs used no network,
read-only root, 256 MiB/no swap, 0.5 CPU, 128 MiB noexec/nosuid temporary storage,
GOMEMLIMIT=128MiB and a 192-file-descriptor soft limit. All 128 chunks reclaimed
under that descriptor limit. Both containers exited zero without OOM.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Linux test binary: `/tmp/zasp-lineage-reclaim-linux.lg95Os/sensor-agent.test`,
SHA-256 `980199172a6b7a8fce4ef881387c024a7eb8721def782d1bca98e8c12cefb319`.
Production Linux binary: `/tmp/zasp-lineage-reclaim-linux.lg95Os/sensor-agent`,
SHA-256 `91b7e6ba78bf62d5e526f220af76feb265a40ab58a70994ba340dd3c9a278329`.
The Linux test binary predates only the final copied-intent test, not product code.
Logs: `/tmp/zasp-lineage-reclaim-linux.log` and
`/tmp/zasp-lineage-reclaim-linux-permissions.log`.

Following the careful skill, cleanup first inspected the exact two owned exited
containers. Their metadata is retained at
`/tmp/zasp-lineage-reclaim-linux-inspection.json`; only
`zasp-lineage-reclaim-20260910-a` and `zasp-lineage-reclaim-20260910-b` were removed.
Their disposable writable state is gone. Logs and binaries remain.

Independent review found no concrete deletion-safety blocker after corrections,
conditional on the Linux sync-failure and actual TLS/PostgreSQL tests, which passed.
This is bounded-component review, not whole-branch shipping or daemon approval.

The complete root `npm run verify` passed on pinned Node 22.23.1, including
1,180 UI tests, typecheck, lint, API/tenancy/release checks, production build and
compiled import checks (seven client chunks, eight server chunks).
Log: `/tmp/zasp-lineage-reclaim-root-verify.log`.

The next checkpoint-deletion primitive is verified separately in
`docs/internal/2026-09-11-sensor-checkpoint-retirement.md`. Consumer completion
authentication follows in `docs/internal/2026-09-11-sensor-consumer-completion.md`.
The subsequent ACK/completion collection handshake and a test-first correction
requiring original ACK durability before initial intent are recorded in
`docs/internal/2026-09-11-sensor-retirement-handshake.md`.

Next: wire bounded rotation and orphan recovery. Remaining M48 acceptance gates, daemon/deployment wiring,
live source compatibility, original sandbox/cgroup/process correlation, full API
and composed Chrome checks and whole-branch review still precede a verified main push.
