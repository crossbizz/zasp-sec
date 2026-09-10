# Runtime lineage now survives ingestion

Status: preservation slice implemented and independently reviewed. Full local
verification and the complete composed pipeline/browser proof passed. PR 33
merged as main `1aab7f58448f13e015ca398c8f483b58b53df5a5`. Push CI
34428832660, PR CI 34428835002 and main CI 34429707297 passed.
This slice grants no M3-46, M3-47 or M7-07 production credit.

The production private runtime ingest API accepts optional `observed_lineage`
for both enrolled source kinds. Adaptation, metadata-only filtering, canonical
archive encoding, archive decoding and batch encoding preserve its exact values.
Present observations are covered by the existing archive digest and receipts.
Absent observations leave legacy canonical bytes and digests unchanged.

The first supported profile is `kubernetes-container-v1`. It requires nonzero,
canonical lower-case UUID-shaped cluster, node, boot and pod identifiers plus a
full `containerd://`, `docker://` or `cri-o://` container identifier with 64
lower-case hexadecimal digits. The UUID check does not assume UUID version 4.
This is an explicit normalization profile, not a claim that every Kubernetes
installation supplies identifiers in this form.

Optional process IDs are positive canonical uint32 decimals and must include a
canonical UTC RFC3339Nano start time after the Unix epoch and no later than the
event timestamp. Optional cgroup IDs are positive canonical uint64 decimals and
still require the complete container qualifications. The existing runtime event
timestamp is millisecond precision; emitters must not round a process start
down or invent a qualifying time to satisfy this check.

Explicit null/empty objects, partial profiles, future versions, duplicate or
case-variant keys, unknown fields, abbreviated containers, leading-zero IDs,
overflow and malformed timestamps are rejected on ingest and archive replay.
The object cannot carry tenant scope, sensor enrollment, correlation-domain,
agent or session authority.

Tetragon's `process.docker` is abbreviated. The full container identifier is
available in `process.pod.container.id`; provider names alone do not supply this
profile's host/boot qualifications. See the official
[Tetragon API reference](https://tetragon.io/docs/reference/grpc-api/) and
[process execution example](https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/).

## What this doesn't claim

Observed lineage is source-provided evidence, not host attestation or permission
to correlate two enrollments. It does not populate the older unqualified
matching fields. The existing confidence algorithm is unchanged: kernel events
remain Unattributed; explicit instrumented identity continues through its
existing Exact path.

The provider adapter still needs configured, qualified host/boot normalization.
Automatic cross-batch Strong and ambiguous Probable attribution remain pending.
Their next authority boundary is immutable, operator-selected OTLP enrollment
pairing with an active, same-scope Tetragon enrollment. The durable batch must
freeze its source/domain binding; candidate snapshots must bind committed
predecessor/archive evidence and a fresh worker lease before side effects.

Snapshot replay must remain byte-stable after revocation or late observations.
Candidate scope, domain, host/boot, event-time bounds, conflicting qualifiers,
distinct agent/session identities and overflow must all be checked. Lineage can
produce Strong, never Exact. Multiple identities must retain unknown IDs.
Process/cgroup matching remains in the original scope and needs composed tests.

## Rollout order

Upgrade every archive consumer before enabling profile emission. Old workers
use closed decoders and reject this new optional field. Do not enable it during
a mixed-version worker rollout. Legacy emitters omit the field and retain their
existing bytes. Once these observations are retained, old consumers are not a
safe rollback target; use a compatible consumer build. No emitter, deployment,
schema migration or live environment was changed by this slice.

## Verification record

The official upstream Superpowers TDD and verification-before-completion
workflow was used because the installed plugin is unavailable. Observation and
ingest tests first failed on the missing type and missing retained field, then
passed. Independent read-only review found no blocker and separately passed
focused race tests. No installed-plugin run is claimed.

- `/tmp/zasp-lineage-observation-red.log`: missing observation type.
- Ingest RED: `/tmp/zasp-lineage-ingest-red.log`.
- `/tmp/zasp-lineage-ingest-green.log`: race tests passed for lineage, events,
  correlation, projection and sensor adapter.
- Full worker race suite: `/tmp/zasp-lineage-worker-race.log`.
- `/tmp/zasp-lineage-harness-red.log` and
  `/tmp/zasp-lineage-harness-green.log`: required composed marker failed first;
  source contracts then passed 19 tests with two explicit harness-only skips.
- Full Node 22 verification passed 196 test files / 1,176 tests, typecheck, lint,
  build, generated API and source/compiled boundaries in
  `/tmp/zasp-lineage-verify.log`. The source release gate passed in
  `/tmp/zasp-lineage-release.log`; its live-environment exclusions remain open.
- `/tmp/zasp-lineage-final-contracts.log`: 46 ledger/harness tests passed, with
  two explicit harness-only skips. Both composed paths ran in the full harness.
- Full Chrome and owned-service proof passed in
  `/tmp/zasp-lineage-chrome-retry.log`, including the required lineage marker,
  session evidence and confidence UI, discovery, Red Team, recovery, tenant
  denial and owned cleanup. The final exit status was zero.

The first composed attempt stopped during pinned-image preparation because
Docker Hub returned a TLS handshake timeout. It never reached the product
pipeline. Owned cleanup completed. The unchanged harness was retried with the
same image digest; no assertion, image pin or environment gate was bypassed.

The composed fixture now sends the same qualified observations from separate
Tetragon and OTLP enrollments. Its required proof reads exact S3 object versions,
checks committed digests and retained fields, runs all five stages, requires
26 kernel events to remain unknown and three explicit semantic events to stay
Exact, and rechecks immutable replay. All required assertions passed in the
owned-service harness. Independent final review found no remaining blocker and
conditioned release acceptance on the full browser result and shipping gates.
The browser and shipping conditions passed. GitHub merge state and successful
main CI 34429707297 were rechecked on September 10, 2026. This ships preservation
only, without granting M3-46, M3-47 or M7-07 correlation task credit.
