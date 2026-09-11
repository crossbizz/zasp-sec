# Enrollment-bound sensor installation

September 10, 2026. Work remains unpublished on `codex/runtime-sensor-lineage`,
based on verified main `a4fede82`. No original task credit changes: 535
production-available, 132 component-only, 61 externally blocked, 728 total.

The production sensor construction now passes its configured enrollment binding
to the actual client and durable file processor. This supersedes the unbound
construction gap recorded in `2026-09-10-sensor-durable-checkpoint.md`.

## Public API through installation

Create and rotate accept one exact optional response-profile header:
`X-Zasp-Sensor-Enrollment-Schema: enrollment-binding-v1`. Unknown, empty,
duplicate or differently cased duplicate map entries are rejected before token
mutation. The profile is captured before repository or credential callbacks.

Omitting the header preserves the existing closed response for older clients.
The new profile adds `enrollment_binding`, a server-derived public hash of the
authenticated Organization, Workspace, Environment and returned sensor ID.
Create and rotate reject a mismatched returned sensor ID. Token rotation keeps
the same binding. A reused sensor ID in another scope gets a different binding.
The hash is a comparison constraint, not authentication or tenant authority.

The response profile doesn't change mutation intent, idempotency digest, token
generation or one-time-token replay rules. Replaying an enrollment mutation
still returns conflict without revealing a token or binding. Tests retain the
same request digest across profile changes. Existing no-store/no-cache and
resource-version handling remain intact.

OpenAPI and the generated client describe the optional legacy-compatible field.
The production UI explicitly requests the new profile; its decoder requires a
canonical 64-character lowercase hexadecimal binding and never falls back to
unbound enrollment. The Tetragon installation instructions show
`sensorAgent.enrollmentBinding=<receipt-binding>` alongside the existing
out-of-band token Secret instructions. Tokens remain out of Helm arguments.

The daemon requires `ZASP_SENSOR_ENROLLMENT_BINDING` before building dependencies.
The customer-edge chart and release renderer require the exact-format receipt
binding and render it unchanged. They don't reconstruct it from names or labels.
A token-only replacement cannot change the binding saved with pending work.
Changing it while old cursor state exists fails closed without rewriting state.

Review also found that the old OTLP enrollment dialog showed Tetragon Helm
instructions. Its new regression failed, then passed after separating the OTLP
instructions and explicitly prohibiting that wrong-source installation. This
doesn't claim a complete OTLP collector installation flow.

## Evidence

The initial response-profile test failed for missing binding and mutation on
invalid headers: `/tmp/zasp-sensor-installation-profile-red.log`. Response-ID
drift tests then reproduced credential disclosure for the wrong returned
resource: `/tmp/zasp-sensor-installation-response-id-red.log`. Both fixes and
the existing public-handler tests pass together in
`/tmp/zasp-sensor-installation-profile-reviewed-green.log` (2.074 seconds).
Independent review found no further concrete blocker in this wiring.

Config and actual production construction failed first in
`/tmp/zasp-sensor-installation-config-red.log`. Full daemon tests now pass in
`/tmp/zasp-sensor-installation-agent-restart-green.log` (2.027 seconds), including
restart with a rotated token, exact pending body replay before appended input,
changed-binding denial and unchanged checkpoint bytes on denial. An older test
expected generic `ErrClient` for expired data; bound requests correctly return
`ErrEnvelopeExpired`. Its assertion now requires that specific error while still
requiring zero transport and zero submitted work. The initial full run is kept in
`/tmp/zasp-sensor-installation-agent-green.log`.

The new composed test uses real product create/rotate handlers and registered
PostgreSQL API/ingest roles, a real file checkpoint and certificate-verified local
HTTPS. After the first accepted response is deliberately lost, actual public
token rotation produces the same binding and a new credential. Restart replays
the identical request and receipt with one artifact write total, unchanged batch
provenance, one batch, five stage rows and one outbox row. An extra poll is idle.
The containing actual database lifecycle suite passes in
`/tmp/zasp-sensor-installation-real-https-postgres-utc.log` (7.852 seconds).
Its first attempt failed because the test supplied a local-time clock to a
UTC-only handler; the production clock contract wasn't changed.

This composition supplies a scoped identity fixture to the public handler, not
browser authentication. The raw artifact store is a synchronized test double.
The server certificate is locally trusted test authority. It doesn't prove S3,
public ingress, actual Kubernetes installation or a complete deployed user flow.

The UI adapter/view regressions and final 11 focused tests pass in
`/tmp/zasp-sensor-installation-ui-final.log`. OTLP instruction RED evidence is
`/tmp/zasp-sensor-installation-otlp-instructions-red.log`. All 1,180 UI tests in
196 files passed before the final instruction-only correction in
`/tmp/zasp-sensor-installation-full-ui-tests.log`. Typecheck and lint passed;
the final corrected UI builds standalone output in
`/tmp/zasp-sensor-installation-build-final.log`.

Deployment rendering failed on the missing new binding contract first; all 36
tests now pass in `/tmp/zasp-sensor-installation-render-green.log` (8.619 seconds).
OpenAPI contracts pass 35/35 in
`/tmp/zasp-sensor-installation-openapi-tests-green.log`. Lint and generated-client
checks pass. UI/API contracts pass 10/10 and coverage reconciles 141 available
operations plus six explicitly planned API-available operations, with no new
coverage credit claimed. Full API race verification is running separately.

The full API race suite subsequently passed in
`/tmp/zasp-sensor-installation-full-api-race.log` (438.170 seconds). That run
preceded the construction-time file collision checks below. After those checks,
the actual PostgreSQL/HTTPS credential lifecycle passed again in
`/tmp/zasp-sensor-installation-final-https-postgres.log` (8.236 seconds).

## Checkpoint input safety

Follow-up review found that a configured log could occupy the checkpoint's
deterministic temporary filename. Orphan cleanup could then remove the input.
The constructor regression failed before the fix in
`/tmp/zasp-sensor-checkpoint-source-slot-red.log`; the test deliberately didn't
run destructive recovery after the unexpected successful construction.

Construction now reserves three basenames: the cursor, its stable lock and its
temporary checkpoint. It compares the identities of opened parent directories
as well as names before creating a lock. A parent-directory symlink can't bypass
the check. Cursor names can't occupy another cursor's lock or temporary namespace.
The production constructor protects the actual token reader's retained parent
and the configured kernel/BTF inputs. Token files must be regular, private files;
leaf symlinks, including projected-token symlinks, aren't supported. The existing
installation must materialize the token as the documented regular file.

All 18 direct/aliased token, kernel and BTF collision cases reject construction,
preserve input bytes and inode, create no cursor state and make no provider call.
Each also checks that the same basename in a separate directory is accepted.
Adapter tests cover log aliases, reserved cursor namespaces and malformed
protected-input descriptors. Full sensor-agent races pass in
`/tmp/zasp-sensor-installation-input-collision-agent.log` (2.187 seconds), and full
adapter races pass in `/tmp/zasp-sensor-installation-input-collision-adapter.log`
(4.888 seconds). Independent read-only review found no concrete blocker in this
repair; it didn't rerun tests or approve shipping.

These checks establish construction-time disjointness. They don't protect against
arbitrary later directory manipulation by another privileged actor. They don't
change the original task counts or certify deployed operation.

## Rollout and remaining work

Roll out migration 48 and supporting server code first, then the binding-aware
UI/install artifact, then the configured sensor. Existing installations must
obtain their same-enrollment binding from a fresh rotate response before using
the new binary. Preserve the original destination, binding and cursor state
during token rotation. An intentional new enrollment requires separately owned
state; don't silently discard or overwrite old pending work.

The inverse rollback must retire binding-dependent clients before removing
migration-48 acceptance support. Database compatibility checks alone don't prove
rolling traffic safety. No live deployment or rollback is claimed here.

Full-daemon resource proof, observed-lineage collection/emission, versioned
correlation-producer activation, remaining migration-48 race/authority cases,
composed browser/release verification and independent final shipping review
remain open. The earlier 256 MiB package stress evidence isn't full-daemon proof.
No push or production-readiness claim is made. Installed Superpowers remains
unavailable; official upstream test-first, verification-before-completion and
independent review are the previously disclosed fallback.
