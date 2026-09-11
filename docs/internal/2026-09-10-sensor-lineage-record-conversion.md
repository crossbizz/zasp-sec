# A closed record before the spool

September 10, 2026. Unpublished `codex/runtime-sensor-lineage` component work.
The full original scope and counts are unchanged: 535 production-available,
132 component-only, 61 externally blocked. This doesn't close M3-46, M3-47 or
M7-07, and no production collector is enabled.

`services/sensor-agent/lineage_event.go` now converts the official generated
Tetragon event types into owned JSON records accepted by the existing normalizer.
It supports the current exec, exit, file-permission and TCP probe shapes without
serializing the provider object. It copies only bounded identity, time and
normalization-input fields. Arguments, working directories, ancestors, labels,
annotations, image metadata, policy messages and opaque extensions don't reach
the record. Binary/file paths and destination addresses are still private inputs
needed by normalization. They are hashed in the final runtime event. The precursor
record is not safe to publish or log; the pending spool needs restricted access.

Unsupported events/arguments, malformed timestamps, missing identity, typed-nil
wrappers, invalid strings, aggregate responses and invalid ports reject without
record bytes. A distinct filtered result covers namespace and process/parent
health-check exclusions. A strictly PID/start-only probe or exit remains partial:
only the downstream generation's exact prior exec cache can complete it. The
converter doesn't manufacture an identity. Nanosecond process start is preserved,
including when the existing normalizer must omit the optional process pair
because it doesn't fit the millisecond event time.

Unknown bytes on event or argument oneof holders now reject, even when a known
variant is present. An older protobuf decoder can retain both, making apparent
support ambiguous. This deliberately rejects benign future fields on those
holders too. Non-oneof process/pod extensions are ignored through field selection;
they aren't copied or interpreted. New provider capabilities need explicit review.

`lineage_request.go` constructs a fresh, caller-independent fixed GetEvents
request. EXEC/EXIT/KPROBE are allowed, health checks and empty/cilium/kube-system
namespaces are excluded, and aggregation is absent. Per-event INCLUDE masks
select the required process fields, parent probe flag and event-specific fields.
The local converter remains mandatory: pinned upstream field filters preserve
top-level metadata, and a filter error can leave the original event in use.
[Field filtering](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/fieldfilters/fields.go),
[server application](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/server/server.go#L155-L173),
[parent health-check rule](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/filters/health_check.go#L56-L68).

## The dependency graph needed another check

The product module now pins official `github.com/cilium/tetragon/api v1.6.0`
and `google.golang.org/protobuf v1.36.10`, with their Apache-2.0 and BSD-3-Clause
licenses recorded in `build/dependencies.lock.yaml` after reading the downloaded
licenses. `go mod tidy` updates the indirect dependencies and checksums. This
doesn't approve importing Tetragon server/code-generation packages.

The earlier temporary compile/tidy/verify proof was insufficient for complete
module inventory. Actual `go list -m all` failed on upstream's nonexistent root
version `v0.0.0-00010101000000-000000000000`, retained in
`/tmp/zasp-lineage-module-inventory.log`. The product module now excludes exactly
that version, with no fabricated replacement. Final tidy, download, inventory and
module verification pass. `/tmp/zasp-lineage-module-inventory-fixed.log` contains
only the official API module under the Tetragon prefix, not a selected root
Tetragon version. The separate temporary proof also passes after that exclusion.

This still isn't live compatibility with the pinned v1.7.0 server. Request masks
are checked against the selected generated descriptors. Executable cross-release
descriptor checks and actual pinned-server subscription remain required.

## Tests and review

Missing converter symbols failed first in `/tmp/zasp-lineage-event-red.log`.
Missing request construction failed in `/tmp/zasp-lineage-request-red.log`.
With the request present, `/tmp/zasp-lineage-parent-filter-red.log` reproduced an
accepted parent health-check event before all three event branches were fixed.
Four ambiguous-oneof regressions failed in
`/tmp/zasp-lineage-unknown-oneof-red.log` before unknown-holder rejection.

Final fresh full sensor-agent races pass in
`/tmp/zasp-lineage-event-dependency-final.log` (2.260 seconds). Coverage includes
actual normalization and observation preservation for the converter's supported
shapes, private-field secrecy, input immutability, exact nanosecond cache keys,
partial exit eviction, invalid/missing values, fixed request serialization and
request-mutation isolation. The accept-probe case is synthetic: the current
deployed policy emits tcp_connect, so no deployed accept-event claim is made.
All 81 dependency tests pass in `/tmp/zasp-lineage-dependency-tests.log`.
The dependency and 728-row status validators pass, with no task reclassification.

The final product module cross-builds for Linux arm64 with Go 1.25 and CGO
disabled. The binary at `/tmp/zasp-lineage-event-build.napGca/sensor-agent` has
SHA-256 `8a5bc32299fbb02c9123de805bcfe93ba66253a3521006a4f6d026634fa5daae`.
`/tmp/zasp-lineage-compiled-module-inventory.log` confirms that only the API
module under the Tetragon prefix enters the compiled package graph. This is a
build check, not execution of the new collector on Linux.

Independent read-only review found no remaining component blocker and accepted
the oneof correction and exact invalid-version exclusion, conditional on the
final module/build checks. It did not approve shipping or live discovery.
Installed Superpowers remains unavailable; the disclosed official upstream
test-first, verification-before-completion and independent-review fallback was
used. Those instructions required the failing regressions and fresh checks.

The next work is still the authenticated single local connection, bounded
receive, private spool/manifest lifecycle and generation ownership. Then wire the
daemon and least-privilege deployment, verify source loss/reconnect and resource
limits, and complete source-to-API-to-browser attribution. No push is made here.
