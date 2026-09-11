# Running sensors and Secret updates

The subsequent [executable replay record](2026-09-11-sensor-daemon-token-replay.md)
adds local running-daemon proof. Deployed Kubernetes acceptance is still open.

The customer-edge consumer now reads the current projected Secret on every send.
The startup copy and its emptyDir volume are gone. This is component and chart
proof, not live Kubernetes or end-to-end production acceptance. Counts remain
535 production-available, 132 component-only and 61 external gates across 728 tasks.
No task credit, main push or activation occurred in this slice.

`ZASP_SENSOR_TOKEN_SOURCE` must be explicit for the lineage consumer. `owned-file`
preserves its existing consumer-owned 0600 single-link regular-file reader.
`kubernetes-projected` selects the Linux-only reader and requires the `token` key.
Unknown or missing modes fail configuration; legacy consumers reject this option.
The chart mounts the Secret directly, read-only, without subPath. The producer
still has no product-token mount. The layout initializer doesn't read credentials.

The reader pins the volume between sends, not a timestamp directory or token.
For each read it checks a root-owned, consumer-group volume on an actual read-only
mount, the canonical visible link and `..data` publication, the timestamp directory,
and an 81-byte root-owned 0440 file in the consumer group. File and directory
identities, both publication links and mount flags are checked again before return.
Unexpected ownership, extra links, writable files, symlinks in the data path,
oversized/short/malformed values and incomplete publications return a fixed error
without token bytes. There is no cached-credential fallback or credential logging.

Version directories must be 0755, optionally setgid. The volume root can retain
tmpfs/emptyDir permission bits, including sticky/setgid; its verified read-only
mount prevents consumer writes. This distinction follows the pinned upstream
[Secret volume setup](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.35.5/pkg/volume/secret/secret.go),
[atomic writer](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.35.5/pkg/volume/util/atomic_writer.go)
and [fsGroup permission handling](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.35.5/pkg/volume/volume_linux.go).
It doesn't prove that a deployed cluster has this layout or ownership.

Local retirement and slot release still work without a token in both configured
modes. A Secret update doesn't rewrite a retained upload envelope. Authentication
and server-side credential lineage/replay acceptance remain separate concerns.
A successful read is a checked snapshot, not a guarantee that a credential cannot
be revoked after the read or a promise about kubelet refresh latency.

## Proof retained

Configuration rejection and the chart change had observed failing tests before
implementation. The initial Linux reader stub failed all four valid-publication
cases. Its failure log is `/tmp/zasp-projected-token-red-reader2.log`; chart RED is
`/tmp/zasp-projected-token-chart-red.log`. Two earlier container commands accidentally
used the image's default entrypoint, exited 1 without running tests, and aren't
counted as RED or GREEN proof.

Two separate containers then exercised one long-lived reader: a root fixture writer
had the projection mounted RW; the UID/GID 65532 reader had it RO and dropped all
capabilities. Twenty cases passed, including rotation, missing/malformed recovery,
file/directory/link ownership and permissions, hardlinks, traversal links, a FIFO,
and invalid lengths. The ordinary visible link remains unchanged across updates.
A separate non-root container with an actually writable mount was rejected.

The final bounded run also published 200 versions while the same reader made
1,000 attempts: 988 returned exact published fixtures and 12 failed closed.
The final version was observed after the writer finished. This is concurrent
fixture evidence, not deterministic coverage of every syscall race boundary.
Both final containers had no network, 192 MiB memory with no extra swap, 0.5 CPU,
64 PIDs, 192 file descriptors and a read-only root. Only the root fixture writer
had CHOWN/FOWNER. No production test hook or privileged reader was added.

Final evidence:

- `/tmp/zasp-projected-token-stress-{writer,reader}.log`: 20 cases plus concurrent publications, both exit 0.
- The writable-mount rejection is in `/tmp/zasp-projected-token-final-writable.log`.
- Full host sensor-agent race suite: 108.782 seconds, `/tmp/zasp-projected-token-agent-race.log`. The subsequent extra configuration/cleanup tests also passed; Linux-only reader execution is covered by the container proofs.
- `/tmp/zasp-projected-token-chart-green.log`: all 41 selected release/staging tests pass.
- Root `npm run verify` passes in `/tmp/zasp-projected-token-root-verify.log`: 196 UI test files, 1,180 tests, typecheck/lint, API/tenancy/contracts, production build, seven client/eight server chunks and the 728-row ledger. This isn't a fresh Chrome test.

Final Linux arm64 artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `/tmp/zasp-projected-token-sensor-agent` | `9148d48613415235c1a4f3267aacb0a2a1d1758ebd99213103ae7c183794c9a1` |
| `/tmp/zasp-projected-token-stress.test` | `5b5491969d0261617071e1156d9a73fee153454de1cc9f04d36dce0b82d60dfb` |

Independent review found no concrete blocker in this bounded reader/config/chart
slice. Superpowers isn't installed; the previously disclosed official upstream
test-first, verification and independent-review workflow was used. The careful
skill required exact stopped-container inspection before cleanup. All 11 owned
containers and eight disposable volumes were removed; logs, binaries and inspection
records remain at `/tmp/zasp-projected-token-containers.json` and
`/tmp/zasp-projected-token-volumes.json`. No OOM kill occurred.

Still open: actual Kubernetes v1.35.5 projection/ownership and running-daemon
rotation, unchanged pending-envelope replay through real authenticated ingestion
after rotation, controlled legacy backlog transition, live Tetragon-to-browser
acceptance, the original sandbox/container/cgroup/process scope, M48 gates and
whole-branch release review. M3-46, M3-47 and M7-07 remain open.
