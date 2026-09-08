# M3-52d runtime queue/archive/index closure

Status: implementation, independent review, local combined pipeline, migration
race, and fresh-build Chrome verification passed. Final release checks and
main CI are tracked below; no managed deployment is claimed.

The original deliverable is a normalized event batch through SQS, S3 archive,
and OpenSearch, with matching references, idempotent replay, and an empty DLQ.

The production coordinator and stage executors are mounted, but their
isolated unit fixtures did not establish this combined path. This slice
exercises them with the existing disposable PostgreSQL migration/principal
harness, owned pinned LocalStack and OpenSearch containers, actual AWS SDK and
OpenSearch drivers, and exact database authorities. Test-only endpoints must
remain confined to the harness. No production endpoint validation is relaxed.

Verification covers authenticated ingest, durable outbox publication,
coordinator delivery, archive/index receipts, downstream completion and queue
acknowledgement, repeated delivery without duplicate effects, tenant denial,
and owned cleanup on normal exit or interruption. Graph-store fixture limits
are explicit because managed graph infrastructure is not exercised.

Superpowers test-first development, fresh verification, and independent
review preceded M3-52d promotion. The runnable UI and release gates remain
mandatory before a push. Live managed cloud observations remain external.

The combined run found a production integration defect: `jobqueue.Queue`
serializes the durable runtime `authority_digest`, but the SQS driver's strict
canonical envelope omitted that field. Production runtime publication failed
before calling SQS. A queue-to-driver regression reproduced the rejection
with `provider called=false`. The driver now preserves the optional lowercase,
nonzero SHA-256 digest through publication and consumption, while retaining
strict canonical encoding and rejection of malformed digests. The race-enabled
queue/driver suites pass. Full combined verification now passes.

Repeated physical SQS publication also exposed a v15 delivery-key conflict.
The forward v36 migration validates tenant, batch generation, and the durable
outbox digest before recognizing a duplicate. Terminal duplicates may be
acknowledged without rewriting the prior receipt. An exact active duplicate
uses `ack_duplicate` only while both the original lease and visibility deadline
remain live. An expired lease or visibility deadline permits atomic physical
message takeover; the original message ID and lease token cannot heartbeat,
release, or acknowledge the replacement. Unknown outcomes stay fail-closed.

The v36 migration pins semantic fingerprint
`8b04d86fd127ae1e1d3b54414cf467d06816faa2fad8f9b92f0f2a5a83550ac6`.
The PostgreSQL race test verifies upgrade, downgrade, exact v35 fingerprint
restoration, and readiness rejection after a PUBLIC execute grant or acceptance
helper definition drift. Deployment
hooks and API schema checks now require/support v36.

Previously accepted HTTP ingest retries also failed once the batch advanced
beyond `queued`. The handler and repository now accept recognized processing
or terminal states only on a database-confirmed replay, after exact artifact
and finalization validation. This replays original acceptance, not a claim
that processing succeeded. Unknown or invented states still reject. Migration
36 widens the corresponding commit helper's replay branch while retaining its
exact request, artifact, job, and outbox checks. The helper definition, owner,
and ACL participate in the pinned fingerprint; downgrade restores the prior
queued-only branch. Independent review approved this change and reran the
PostgreSQL migration/rollback/drift test under the race detector.

SQS may return distinct physical messages for the same canonical job in one
receive batch. The queue facade and driver previously rejected that batch.
They now accept repeated job IDs only when the validated canonical SHA-256
matches; changed payloads, repeated physical IDs, and repeated receipt handles
still reject. The regression failed before the fix and the complete queue
race suites pass. Receipt mutations remain individually bound to each physical
delivery and require unique entries within each provider write batch.

Independent review identified slow container startup blocking signal cleanup.
Image pulls now run separately without creating containers; actual starts
use already-pinned local images with a 10-second bound. Ownership inspections
and deletion each have a 3-second bound, and other harness cleanup runs even
if Docker cleanup fails. Unit coverage includes interrupted pending starts,
cold image preparation, mismatched ownership, and public-binding rejection.
The opt-in real SIGTERM test passed with two running owned containers,
PostgreSQL, child processes, and the temporary root all removed.

## Final verification

- The actual local pipeline passes both alone and in the full installed-Chrome
  run. It proves authenticated ingest, tenant/generation denial, durable outbox
  publication, five production stage receipts, matching S3/OpenSearch identity
  and digest, one index version, unchanged archive versions and stage rows,
  active duplicate acknowledgement, expired lease/visibility takeover, stale
  owner fencing, terminal ingest replay, and six physical SQS acknowledgements.
- Replay polling waits for actual provider acknowledgements with an exact
  count and bounded retries. One short poll after a visibility deadline does
  not prove receipt. Final visible, in-flight, and delayed counts are all zero
  for both queues; actual receives are empty. Independent review approved this
  assertion-preserving correction after the one-shot test failed.
- `npm run production:combined-e2e:test` passes after a fresh production build:
  12 harness/helper tests pass; the real-container SIGTERM test is opt-in and
  passed separately. The full browser flow covers discovery, multi-tenancy,
  Security Agent actions, recovery, administration, restart/reload, and a clean
  browser exception stream.
- `npm run production:release:gate` passes source SBOM, license, container,
  secret, resilience, and dependency checks.
- Superpowers test-first and verification-before-completion practices were
  used; independent read-only Astra review approved production semantics,
  migration rollback/fingerprint coverage, and final polling assertions.
- Only M3-52d is promoted: 515 production-available, 152 component-only,
  61 blocked/external, zero missing. The ledger has all 728 original IDs.
- Fresh full affected race suites pass: API 322.660s, migration command 71.827s,
  migrations 4.230s, runtime events 4.945s, raw store 3.503s, queue 1.317s,
  SQS driver 2.033s, and worker 9.619s. The migration test covers actual
  PostgreSQL up/down/re-up and security/definition drift rejection.
- All 21 ledger regression tests pass; the new M3-52d demotion guard was
  observed failing before the audited ledger update and passing afterward.
- Fresh `npm run verify` passes: 184 Vitest files / 987 tests, type-check,
  lint, API contracts, tenant checks, release tests, source/compiled production
  import checks, production build, and all 728 ledger rows.
- Branch/main CI: pending after push; no remote CI pass claimed yet.

## Limits

The proof uses actual local SQS/S3/KMS emulation and OpenSearch with production
SDK drivers and database principals. Correlation/projection graph stores are
explicit fixtures, not Neo4j evidence. It does not prove managed cloud IAM,
customer credentials, public DNS/TLS, or deployment. Those external gates are
unchanged. Deploy schema v36 before rolling the corresponding API/workers.
