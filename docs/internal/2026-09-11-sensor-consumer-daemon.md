# Non-root consumer executable

The explicit `lineage-consumer` role now discovers and processes producer
generations through fixed consumer slots. This is component evidence, not
deployment acceptance. The 728-task totals remain 535 production-available,
132 component-only and 61 external gates. No credit for M3-46, M3-47 or M7-07.
No activation or push.

## What changed

The role requires separate spool, ACK, private-state, product-token, kernel,
BTF and Kubernetes service-account directories. Legacy log/cursor configuration
is rejected in this role. Unset or `legacy-consumer` keeps the existing path;
unknown roles fail closed. Production construction requires Linux and a non-root
UID, and admits root-owned producer metadata. No raw Tetragon socket is opened
by the consumer.

Construction pins protected inputs and checks both resolved path ancestry and
physical-root separation before a writer action. It doesn't need an upload token
file to exist, and doesn't demand a settled producer inventory at startup. Each
tick still validates the complete bounded inventory before mutations. Kubernetes
client construction still needs its service-account credential; credential-free
cleanup here means independent of the product upload credential.

Token reads require consumer ownership, one link, a regular file, mode 0600 and
the exact canonical 81-byte credential. They use no-follow open and compare the
named/opened inode and metadata before and after reading. Each send rereads the
file. The dependency-level token method uses the same strict reader.

Local retirement/release runs before upload work. A fixed, credentialless request
to `http://127.0.0.1:8082/readyz` then checks producer readiness with a one-second
deadline and a 128-byte exact response bound. Redirects and encoded responses
aren't accepted. Producer failure marks the runtime degraded but never prevents
the local cleanup attempt or invents a dropped-event count. Existing node probing
and cluster reporting wrap the new runtime.

One operation deadline bounds upload reconciliation. A process-lifetime scheduling
hint advances before each attempted generation, so a canceled first upload won't
consume every later tick. Retirement stays first. The hint grants no identity or
deletion authority, is serialized under the reconciliation mutex, and resets on
restart. All source and assignment checks remain in place.

## Verification and limits

The canceled-upload regression first failed on the second tick, then passed with
cyclic scheduling. Controller race tests passed in 7.640 seconds. Combined daemon,
configuration, heartbeat and controller races passed in 7.993 seconds. The full
sensor-agent race suite passed in 110.007 seconds. The separate actual local
HTTPS/PostgreSQL installed-sensor regression passed in 40.426 seconds; it tests
the existing controller/API composition, not the new compiled daemon's server.

The compiled production consumer runs as UID/GID 65532 with zero effective
capabilities in the new Linux composition. Its TLS upload endpoint, producer
readiness endpoint and Kubernetes API are fixtures. It uploads one qualified
root-owned chunk, produces a verifiable receipt, and remains live but unready
while cluster authority returns 503. After the synthetic product token file is
removed, root reclamation and consumer checkpoint/assignment retirement complete.
An owner-UID subprocess verifies the final two lock files before SIGTERM. The
daemon joins cleanly, performs no duplicate upload and doesn't print credentials.
Token-file removal is not server-side token revocation.

Final Linux checks ran three repetitions each: compiled producer and consumer,
root/non-root original and recovered lifecycles, ordinary non-root daemon tests
and the consumer controller suite. No selected test skipped or failed; no OOM.
Containers had no external network, a read-only root, 256 MiB memory with no
additional swap, 0.5 CPU, 128 PIDs, 192 file descriptors and bounded private tmpfs.
The root test harness had SETUID/SETGID/CHOWN/KILL. KILL is needed to signal its
different-UID child; the actual consumer had zero effective capabilities.

Early fixture failures are retained: a random TLS port violated the production
configuration's standard-port requirement; a later harness lacked KILL and
couldn't join its non-root child. Neither run counts as final evidence. The
fixture now uses standard HTTPS and checks the harness capability before startup.
Independent review found no remaining concrete blocker in this bounded slice.
Superpowers isn't installed; the previously disclosed official upstream
test-first, verification and independent-review workflow was used.

Evidence retained on this host:

- `/tmp/zasp-lineage-consumer-fairness-red.log` and `-green.log`.
- `/tmp/zasp-lineage-consumer-daemon-focused.log`, `-full-agent.log` and `-installed.log`.
- `/tmp/zasp-lineage-consumer-daemon-linux-final-composition.log` and `-final-ordinary.log`.
- `/tmp/zasp-lineage-consumer-daemon.3a1gRd/sensor-agent`, SHA-256
  `6254b8e0bd9f15c9febbf64a2012dc49202e7797d1ff7df082816977a9516cdf`.
- The Linux test binary in that directory, SHA-256
  `06e0fd40a185c87831705400b4a5dc97c17de7517506f2d9feaa8dc1dbfa8925`.

The ledger check and all 27 checker tests pass. All five exact-owned containers
(`zasp-lineage-consumer-daemon-linux-a` through `-e`) were inspected and removed;
no matching container remains. Their metadata is retained in
`/tmp/zasp-lineage-consumer-daemon-linux-inspection.json`. The earlier harness
failure container was stopped explicitly. Logs and binaries remain on disk.

Installation manifests, ownership initialization, mount/token isolation, RBAC,
live pinned Tetragon-to-browser acceptance, original sandbox/container/cgroup/
process coverage and the remaining M48 gates are still open. Whole-branch tests,
UI verification, browser proof and independent release review remain push gates.
