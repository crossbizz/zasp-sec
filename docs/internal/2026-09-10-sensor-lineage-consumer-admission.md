# Read admission keeps the original source binding

September 10, 2026. Unpublished work on `codex/runtime-sensor-lineage`.
Counts remain 535 production-available, 132 component-only and 61 external
gates. No task promotion, deployment or push.

The new read-only spool reader admits a generation for an expected enrollment.
That expected value comes from the consumer's trusted installation, not from the
manifest it is about to read. The original manifest supplies the copied source
context; the reader doesn't attach a current boot identity to old records.

## What admission checks

The reader pins the spool parent, named generation directory and manifest file.
It checks producer ownership, protected directory modes, the published 0750
generation mode, exact 0440 manifest mode, one link, regular-file type and named/
held inode agreement. The canonical closed manifest must use the supported
format, match the generation UUID in its directory name, contain a valid source
and node name, and match the expected enrollment.

Production construction is Linux-only with expected producer UID zero. Explicit
owner injection supports local fixtures. Controlled mounts and installation
configuration still supply the trust boundary; a caller-selected path or UID
doesn't provide host attestation or enrollment authority.

There are no credential reads, producer-lock acquisitions, writes or deletes.
The reader can operate while the producer holds its exclusive lock. It checks
parent-to-generation and generation-to-manifest identity before and after reads.
A replaced named directory or manifest isn't accepted as the admitted source.
Source access returns a copy; returned chunk bytes belong to that read and aren't
retained as mutable reader state.

## Missing isn't consumed

Chunk reads enforce canonical numbered names, source/manifest binding, checksums,
record and byte counts, expected ownership/modes and the existing closed record
shape. They don't replace semantic normalization. Each returned chunk includes
its sequence, payload digest and owned record slices.

Directory enumeration is bounded and rejects unknown chunk names, unsupported
files, bad metadata and oversized entries. `.pending` may be observed during
publication, but its contents aren't read. Missing requested chunks don't advance
anything. If a later chunk or seal establishes a gap, the read fails; the requested
name is rechecked to avoid treating an overlapping publication as a contradiction.
A missing chunk can also be past a verified seal. The caller must inspect closure
and its own committed prefix before deciding what that means.

## A seal still isn't an acknowledgment

Seal reads check version, manifest hash, allowlisted termination reason, bounded
counts and `coverage_complete: false`. After observing a seal, the reader takes a
fresh directory view, checks every claimed chunk in sequence, compares cumulative
record/byte totals, then rechecks seal bytes and source identity. An incomplete
directory view taken during publication doesn't supply final closure totals.

Accepted payload totals cannot exceed 8 MiB. Verification stops when accumulation
crosses that limit; detecting a corrupt total can require reading one extra bounded
chunk. At most 128 chunks are considered. Repeated seal calls reread the generation.
Reads and Close are serialized filesystem operations without a hard cancellation
deadline. This is an explicit cost for the future consumer to control.

Successful closure verification proves local structural consistency only. It
doesn't prove the records were normalized, uploaded, acknowledged or completely
observed upstream. Unsealed abandoned generations remain readable evidence with
unknown termination. Nothing here authorizes reclamation.

## Evidence

Missing-implementation RED: `/tmp/zasp-lineage-spool-reader-red.log`.
Three focused host race runs pass in
`/tmp/zasp-lineage-spool-reader-focused.log` (3.478 seconds). Fresh full
sensor-agent races, including final enrollment, unsealed-gap and coverage cases,
pass in `/tmp/zasp-lineage-spool-reader-full-agent.log` (25.001 seconds).

Tests reject foreign/empty enrollment, wrong owner, writable parents/directories,
unpublished directories, symlink or writable manifests, oversized metadata,
generation/format disagreement, sealed and unsealed missing-middle chunks,
incorrect seal counts, complete-coverage claims, unsupported names and special
files. They also cover named directory/manifest replacement after admission and
caller mutation of returned records.

A paused actual publication test reads while `.pending` exists and the producer
holds its lock. The reader reports no chunk or closure, then reads the complete
published chunk after the writer resumes. No production filesystem hooks or
synthetic chunk data substitute for that publication.

Independent read-only review found no concrete blocker in this read-admission
component. Installed Superpowers remains unavailable. The disclosed official
upstream test-first, fresh-verification and independent-review workflow supplied
these checks. No durable-checkpoint, acknowledgment, reclamation or shipping
approval is implied.

All reader tests passed three repetitions on Linux arm64. The final output is
`/tmp/zasp-lineage-spool-reader-linux-final.log`. The parent test process ran as
UID 0/GID 65532, created the actual producer-owned files, and started a UID/GID
65532 child. That child read the chunk and verified closure, but got permission
denials opening the chunk, pending path or producer lock for writing. This isn't
merely a configured-owner mismatch test. The stricter final assertion requires
permission errors, not arbitrary failures.

The container used a read-only root, no network, 256 MiB memory without swap,
0.5 CPU, GOMEMLIMIT 128 MiB and a 128 MiB tmpfs. Only SETUID/SETGID were added for
the identity-switching fixture; this isn't a proposed production capability set.
Both owned proof containers exited zero without OOM, were inspected and removed.
Logs and binaries remain. No full-daemon resource or persistent-disk durability
claim is made.

Final test binary: `/tmp/zasp-lineage-reader-linux.Kc4Abj/sensor-agent-final.test`,
SHA-256 `87cbe54952c699df3ec281aa367fa7d6113889675227eb3e690a8e20f134c06e`.
Production cross-build: `/tmp/zasp-lineage-reader-linux.Kc4Abj/sensor-agent`, SHA-256
`9d1360e05d5a8f9088b078693b4ddd49ab775debc4e5645b544b62865ac208e3`.
Pinned local image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.

Next: persist the admitted sequence/digest, process cache and exact frozen upload
before sending. Only a verified durable consumer acknowledgment may permit the
producer to reclaim these generations.
