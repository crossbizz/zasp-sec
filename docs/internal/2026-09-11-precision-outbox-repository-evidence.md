# Explicit precision outbox repository, local evidence

NewPreciseRuntimeOutboxRepository binds the compiled release-51 checksum and
semantic fingerprint to the outbox principal. It accepts a scalar true readiness
result only and never falls back to historical schema readiness. Existing
construction remains unchanged.

The explicit path claims through zasp_runtime_claim_outbox_v2 with the existing
five arguments. Claim, heartbeat, acknowledgement and retry each check fresh
readiness before operation SQL. Existing topic, scope, lease and result checks
remain in place.

TDD evidence: historical construction rejected the release51-only database;
the claim test caught selection of the old entry; fifteen transition cases
caught operation SQL running without fresh readiness. After correction, focused
outbox repository races passed in 1.954s. These use declared database responses,
not actual PostgreSQL/provider E2E evidence. Final no-fallback/nil-database tests
passed with the historical regression suite in 1.905s. Independent Go review
found no blocking findings and repeated precise repository races in 1.626s.

The SQL extension's final-pin actual-PostgreSQL suite passed in 326.450s, following
focused migration/delivery checks (91.998s), other-topic/fairness checks (5.409s)
and migration races (1.591s). These satisfy its independent review's conditions.
Semantic fingerprint: 5242726e1989e8f0305819820c8baa5e574fc6c65f4bf5b5b3b37a3d6cc1355f.
Checksum: 7db9be0f0e012eeeb5a7adf6bd405e7d96c78b27a3e9fe5c42362680bf7dce15.

The explicit publisher core now admits V1/V2, checks fresh precision readiness
before token generation/claim and preserves the stored payload bytes and digest.
Historical construction remains V1-only. TDD caught both historical V2 rejection
and unready authority claiming work. Outbox races passed in 2.310s, full worker
races in 19.122s, and extra typed-nil/topic/schema tests in 2.197s. Independent
core review found no blocking findings and repeated targeted races in 2.459s.
These publisher checks use declared provider responses, not a deployed queue.

ReadyPrecision is now exported on the outbox repository for production wiring;
it refuses legacy construction and invalid contexts before database access.
Its interface regression failed before implementation; focused repository races
passed in 1.904s and independent wrapper review found no findings.

Production outbox selection now uses ZASP_RUNTIME_DELIVERY_SCHEMA=runtime-event-v2
to pair the precise repository and publisher. Empty/v1 retain old construction.
Only coordinator/runtime-outbox accept a nonempty selector. The composed-worker
test publishes a real V2 envelope through the repository/processor with declared
database/provider responses, checks scoped acknowledgement and original bytes/
digest, then refuses further claims after cached-healthy readiness drifts.
It failed before selection was wired; the corrected race test passed in 2.100s.
Changing only the processor selection to legacy reproduced failure (0.902s).
After restoration, full worker races passed in 18.899s. Independent review found
no blocking findings and repeated targeted races in 2.114s. Extra environment
allowlist/whitespace and unrelated-mode tests passed in 2.303s. UI build passed.

Full provider pipeline and explicit schema51 rollout remain pending. No
deployment, push or original task credit follows from these prerequisites.
Replace all old queue coordinators before enabling V2 producers.
