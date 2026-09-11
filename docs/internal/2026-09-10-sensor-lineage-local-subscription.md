# One checked local connection

September 10, 2026. Unpublished work on `codex/runtime-sensor-lineage`.
Original task counts remain 535 production-available, 132 component-only and
61 externally blocked. No collector deployment, lineage activation or push.

The trusted Tetragon-side producer now has an authenticated Unix endpoint and
an actual gRPC subscription component. The sensor consumer still must not receive
the raw socket, which grants Tetragon control methods as well as event access.

## What the endpoint checks

`lineage_socket.go` pins the parent directory, requires its expected owner and
no group/world writes, and checks socket type, owner, link count and absence of
world access. The original socket identity is fixed at construction. Linux keeps
an `O_PATH|O_NOFOLLOW` handle to the socket itself, preventing inode reuse after
unlink. Both the held inode and pathname are checked before/after dialing.

Linux connects through `/proc/self/fd/<parent-fd>/<leaf>` and validates
`SO_PEERCRED` before exposing the connection to gRPC. A renamed/replaced parent
pathname cannot redirect the connection. One attempted dial consumes the
endpoint, including failed attempts. Close serializes with dialing, revokes the
connection and releases the pinned handles. The dial has a three-second limit;
that limit doesn't cover preceding filesystem operations or mutex acquisition.
The deployment must supply trusted local mounts, not arbitrary remote filesystems.

Production construction is Linux-only with expected UID zero. The Darwin helper
uses `LOCAL_PEERCRED` and path rechecks for local fixtures, without production
authority or the Linux inode-pinning claim. Peer UID and protected paths aren't
image attestation or proof of the host/Pod namespace. Deployment supplies that
trust boundary; repeated boot/Node checks still belong to generation creation.

## The stream and its lifetime

`lineage_subscription.go` owns the checked endpoint. It uses a fixed local
target and the single-use dialer, disables proxy resolution and service-config
overrides, and applies 256 KiB receive, 16 KiB send and 16 KiB header limits.
It accepts exactly the expected `v1.7.0` version response before requesting events.
That response is a compatibility gate, not proof of the server image. Startup
has a three-second deadline and honors earlier parent cancellation.

Only the fixed request builder is used. Caller outgoing metadata is cleared for
both RPCs, preserving cancellation but not forwarding caller credentials or scope
headers. Next reads the stream and calls the owned record converter. Filtered and
invalid records return distinct nonterminal errors for future exclusion/drop
accounting. Transport failure closes the generation permanently. Lifetime checks
before/after receive and after conversion prevent already-received data from
being returned once cancellation is observed. Close cancels blocked reads without
taking their receive lock.

Configured retries are disabled. gRPC's transparent retries for unwritten or
server-unprocessed RPCs are separate; the library can perform them on the same
checked connection. The one-attempt endpoint prevents a new physical connection.
No explicit resubscription occurs after a receive failure. This isn't a guarantee
of a single HTTP/2 request attempt or lossless event delivery.

## Failures caught before acceptance

The first endpoint and subscription tests failed on missing implementation in
`/tmp/zasp-lineage-socket-red.log` and `/tmp/zasp-lineage-subscription-red.log`.
Independent review found that retaining only FileInfo didn't pin the original
socket inode. The Linux handle regression failed first in
`/tmp/zasp-lineage-socket-pin-red.log`; the implementation now retains that inode.
Tests also cover concurrent Close and an actual non-root peer whose socket file
has been changed to root ownership, not merely a filesystem-owner mismatch.

Actual gRPC regressions then demonstrated two lifecycle/privacy defects:
`/tmp/zasp-lineage-subscription-metadata-red.log` captured caller metadata reaching
the source, and `/tmp/zasp-lineage-subscription-cancel-red.log` captured an event
returned after cancellation. The latter holds an event received over real Unix
gRPC at the test's receive boundary, making the race deterministic without adding
production test hooks. Both regressions pass after the fixes.

Final fresh full sensor-agent races pass in
`/tmp/zasp-lineage-subscription-reviewed-agent.log` (2.669 seconds). All 81
dependency tests pass in `/tmp/zasp-lineage-socket-dependency-tests.log`; module
tidy/inventory/verification and the dependency validator pass. Direct x/sys and
gRPC dependencies now have their inspected BSD-3-Clause and Apache-2.0 licenses
recorded in the dependency lock. The Tetragon module inventory still selects
only the official API module, not the unpublished root placeholder.

The final Linux arm64, CGO-disabled test binary is
`/tmp/zasp-lineage-socket-linux.y8w9Lr/sensor-agent-final.test`, SHA-256
`a5f3323aa4366c7e4e2f7694f0b183d6d73224847db4533a495b3cf841d57e22`.
All socket/subscription tests passed three repetitions in an isolated container
under 256 MiB memory, 0.5 CPU, no network and a read-only root, with only
SETUID/SETGID/CHOWN added for the peer-identity negative fixture. Output is in
`/tmp/zasp-lineage-subscription-linux-final.log`. Exit was zero and OOMKilled was
false. The inherited image health check isn't relevant to this test entrypoint;
no production health or full-daemon resource claim is made. Both owned proof
containers were inspected and removed. Logs and binaries remain.

The production binary also cross-builds at
`/tmp/zasp-lineage-socket-linux.y8w9Lr/sensor-agent`, SHA-256
`c666f02059191637a93c75ebbd893428aa012483e8e12ad161d21ae47d8175cd`.
Independent read-only review accepted the endpoint repair and final lifetime/
metadata corrections as components. Installed Superpowers remains unavailable;
the disclosed official upstream test-first, fresh-verification and independent
review workflow required these regression checks. No shipping approval.

The gRPC server in these tests is a local fixture using official generated
bindings, not a running Tetragon v1.7.0 daemon. Live pinned-server compatibility,
cross-release descriptor checks and real source emission remain open. Next are
the enrollment/boot/Node-bound immutable manifest, bounded private spool, restart
and gap accounting, daemon/deployment wiring and full source-to-browser proof.
