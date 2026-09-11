# File-event cgroup identity

This is the unmerged PR48 M3-46 increment, published at
`f398bb67d51db34a57ab82829ccee2d4419bdbaa`. Push CI 34634470637 and PR CI
34634548903 are running. M3-46 and M3-47 remain open. There is no
new original-task credit, live kernel acceptance or deployed-release claim.

The typed Tetragon producer previously discarded every `ProcessKprobe.Data`
value. The adapter could carry manually supplied cgroup qualifiers but couldn't
derive one from the actual selected provider surface. The new path selects one
unsigned default-hierarchy membership ID from the synchronous
`security_file_permission` hook. The source remains Tetragon, not semantic truth.

## What changed

The exact `zasp-sensitive-file` policy reads `cgroups.dfl_cgrp.kn.id` from
`current_task`, as `uint64`, labelled `zasp_cgroup_v2_id`. It retains the existing
file selectors. Network hooks are unchanged: socket attribution can name a
socket creator different from the executing task, so their data cannot supply
this file-event qualifier.

The selected gRPC field reaches the owned sanitizer as an unsigned `SizeArg`.
The spool encodes it as a canonical decimal string. The adapter applies it only
to that event, after the required cluster, node, boot, pod and full container
qualifiers are established. It never enters the execution cache. A later event
with missing data doesn't inherit an earlier membership.

New producer generations use `tetragon-local-stream-v2` and the paired
`zasp-tetragon-record-v2` format. New readers accept both historical v1 and v2
generations. Pre-v2 readers refuse the new manifest before cursor processing or
ACK; a rollback cannot silently count enriched records as malformed drops.
Unfinished new generations must be drained and reclaimed by a compatible
reader, or preserved for its return. Do not relabel or erase them to downgrade.
Startup reservation recovery accepts every prefix of either exact paired
manifest, retaining generation and enrollment binding.

Malformed presence is rejected: unknown labels, wrong policies/hooks, nil or
unknown protobuf variants, zero, duplicates, overflow, noncanonical decimal
strings, JSON null/empty values and inner or outer case aliases. Rejection uses
the existing producer/consumer loss accounting, never raw payload logging.

The archive, candidate observation schema, frozen matching and receipt versions
are unchanged. Old input without cgroup data normalizes identically under both
reader profiles. The existing matcher still rejects contradictory cgroup IDs.

## Fresh evidence

- `/tmp/zasp-cgroup-source-red.log`: the observed value was discarded before
  spooling; malformed protobuf values became valid events.
- `/tmp/zasp-cgroup-manifest-red.log`: v2 startup recovery failed at prefix 71.
- `/tmp/zasp-cgroup-json-red.log`: inner JSON case aliases were accepted.
- `/tmp/zasp-cgroup-outer-red.log`: independent review found outer `DATA` could
  overwrite malformed presence. The regression reproduced acceptance.
- `/tmp/zasp-cgroup-policy-red.log`: rendered policy omitted the data request.
- `/tmp/zasp-cgroup-daemon-red.log`: historical replay passed, but the new
  acceptance assertion found no cgroup in the uploaded archive. The v2 fixture
  still emitted an exec record. It now emits the typed file-event value through
  the actual sanitizer, spool and daemon, without injecting archived lineage.
- `/tmp/zasp-cgroup-daemon-green.log`: two actual isolated Linux attempts passed
  both v1 and v2 subcases. Non-root daemon, TLS, public enrollment, PostgreSQL
  admission, lost success, token rotation, identical pending envelope/replay,
  one database/artifact authority and verified ACK all passed. The archived
  cgroup is exactly `18446744073709551615`. Successful owned containers were
  removed; the intentional RED's stopped container and host logs were retained.
- `/tmp/zasp-cgroup-legacy-reader.log`: an unchanged test binary built from
  `49faf28d7b762aac0e3fc316962fe8905ae15802` refuses the v2 manifest before
  credentials, HTTP, cursor, dropped-event accounting or ACK. Its historical
  normalization control passes. This is an opt-in local compatibility test,
  not a production-binary test flag or a default CI claim.
- `/tmp/zasp-cgroup-adapter-final-races.log`: adapter and lineage race tests pass
  after the outer-alias fix. Tests cover cached partial execution identity,
  changing membership, absent data, wrong sources and lossless uint64 values.
- `/tmp/zasp-cgroup-sensor-races.log`: complete sensor races passed before the
  final outer-alias, fixture and historical-binary additions.
- `/tmp/zasp-cgroup-sensor-final-races.log`: fresh complete sensor race suite
  passed after those additions, in 112.847s.
- `/tmp/zasp-cgroup-verify.log`: full verification passed all 1,188 UI tests,
  typecheck, lint, build, compiled imports and all 728 ledger rows.
- `/tmp/zasp-cgroup-source-gate.log`: complete source release gate passed.
- `/tmp/zasp-cgroup-receipt-races.log`: runtime event, frozen correlation and
  projection race tests passed with unchanged receipt algorithms.
- `/tmp/zasp-cgroup-postcommit-secrets.log`: all 1,398 commits passed. The
  publication hook's eight nonblocking MEDIUM matches were public CI IDs,
  inspected against exact added lines. There were no HIGH findings or bypass.

Independent review accepted the version fence and event-local semantics, found
the outer-alias defect, and confirmed its fix. It approved incremental
publication conditional on the final sensor race run, which has now passed.
Superpowers
is unavailable as an installed skill; the official upstream test-first,
verification-before-completion and independent-review workflows are the
explicit fallback used here.

## Evidence limits

`kn.id` is default-hierarchy membership at observation time. It is not a cgroup
namespace inode, semantic sandbox ID, cgroup-v1 controller ID or lifetime
interval. Existing boot/container qualifiers remain mandatory. Numeric equality
alone doesn't establish process, tenant or sandbox ownership.

The daemon proof's provider and Kubernetes inputs remain fixtures, and its raw
artifact store is a test implementation. Actual BTF resolution, policy loading,
emitted kernel values and provider readiness still need a supported enrolled
cluster. A rendered policy or protobuf fixture doesn't prove those conditions.
No extra CRI socket, privilege, host mount or network permission was added.

Sandbox binding, its provenance/lifetime/conflicts, and the process timestamp
precision gap remain M3-46 work. Changed sandbox matching must use new frozen
snapshot/receipt semantics, preserving all released v1/v2 replay behavior.

Pinned source references: [Tetragon v1.7 hook data](https://github.com/cilium/tetragon/blob/v1.7.0/docs/content/en/docs/concepts/tracing-policy/hooks.md),
[v1.7 unsigned protobuf conversion](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/grpc/tracing/tracing.go),
[Linux 6.1 cgroup identity](https://github.com/torvalds/linux/blob/v6.1/include/linux/cgroup.h).
