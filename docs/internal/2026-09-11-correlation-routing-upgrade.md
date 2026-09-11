# Correlation routing upgrade boundary

This is the next original-scope implementation boundary after merged PR45. A local
migration49 draft exists but is not shipped or activated. Counts remain 535 production-available,
132 component-only and 61 blocked/external. M3-46, M3-47 and M7-07 remain open.

Independent source review supports a version-aware claim API. The existing claim
body is still in migration15; migration27 adds recovery protection through table
triggers. There is no implementation-version predicate before either the
exhaustion update or eligible-job selection. Filtering returned leases is too
late: an old worker could already consume retries or fail a v2 batch.

The forward change should retain the four-argument legacy entrypoint and make
its correlation path v1-only. A separate upgraded correlation entrypoint admits
exactly v1 and v2. Both use one private implementation with the same stage-wide
advisory lock, live-lease exclusion per organization and fairness table. Apply
the version predicate before both exhaustion and eligible selection. Preserve
scope/generation joins, predecessor digest, delivery visibility, lease ownership,
attempt increments and recovery triggers. Do not rewrite stored versions or
receipts. Keep exact owners, search paths, registered-principal checks and ACLs;
neither PUBLIC nor unrelated stage principals may invoke the upgraded API.

Repository capability must be immutable and explicit. Keep the old constructor's
behavior and select the upgraded entrypoint only for configured v2 readers.
Validate returned versions against that capability. Readiness and direct claim
entrypoints must reject drift, not rely solely on cached worker readiness. Do not
downgrade after a permission error, malformed response or missing function on
schema49. Any schema48 fallback requires independent exact healthy48 validation.

Migration48 rejects later schemas. The upgrade must extend the pinned predecessor
readiness chain, preserving historical checksums and fingerprints while binding
the complete new claim/routing definitions and ACLs. Migration runner, catalog,
CLI and rendered-release expectations need corresponding checks. Old API binaries
also explicitly reject schemas above48. Compatible worker overlap alone does not
prove API availability: account for API binary compatibility before activating
the migration. PR45 by itself does not establish this compatibility.

Required actual PostgreSQL and composed regressions:

- Ingest on48 creates v1; forward migration and fresh ingest create v2 without
  fixture stage-version updates. Old acceptance replay preserves its stages.
- Legacy claims leave v2 pending, retryable, expired-leased and attempt100 work,
  plus related batch/job/delivery rows, untouched while completing v1.
- Upgraded workers drain both versions, preserving v1 receipt bytes and binding
  v2 receipts to their frozen snapshots.
- Concurrent old/new claimers preserve tenant fairness, one live correlation
  lease per organization, attempt counts and exact lease ownership.
- Unauthorized principals, missing predecessors, expired deliveries, stale
  generation/token, recovery holds and unknown versions stay fail-closed.
- Function-body, ACL, checksum, metadata and later-schema drift reject readiness
  and direct claiming before mutations.
- Rollback refuses to restore unrestricted legacy claiming while retained v2
  work exists. Do not relabel or delete evidence to permit rollback.

The source reviews used the official upstream Superpowers review workflow because
the installed skill is unavailable. These are bounded reviews, not full release
approval. Sandbox, container, cgroup and process lineage,
ambiguity, real producer reachability and mixed-evidence browser acceptance all
remain required under the original plan.

## Local implementation evidence

Migration49 preserves the verified predecessor claim body in a private shared
helper. The legacy entrypoint filters correlation to v1, and an explicit v2
entrypoint accepts v1/v2. Both exhaustion and eligible selection are filtered.
The producer changes only newly committed stages. The runner verifies exact48
before upgrade and exact49 afterward. Empty rollback restores the exact48 live
fingerprint; retained non-v1 correlation or candidate snapshots refuse rollback.
The API draft accepts pinned schema48/49. The local CLI and worker wiring now
support49 activation with explicit48 compatibility staging. Main still targets48.

An already-entered old function body can survive replacement while waiting on its
stage advisory lock. A new mutation trigger therefore also checks compatible
claim declarations before attempt increments and claim-side exhaustion. The
transaction-local marker is not authority or binary attestation. Only the already
registered correlation principal has the new public entrypoint grant. Marker
restoration is tested for success, rollback and caught recovery-hold errors.

Independent review found that the initial trigger also rejected valid completion
at attempt100. Actual PostgreSQL reproduced42501 for both retryable and failed
completion. The corrected guard uses the predecessor's transaction-time lease
expiry boundary for claim-side exhaustion. A live worker now completes without a
marker, updates stage/batch/legacy batch/job/delivery records, and replays the same
receipt. Review also found that pinned readiness accepted damaged installed
fingerprint metadata. Readiness now requires installed checksum and fingerprint
agreement plus the live catalog fingerprint. Neither check claims to withstand a
privileged administrator deliberately rewriting the whole database authority.

Local evidence:

- `/tmp/zasp-correlation-routing-legacy-red.log`: actual legacy claim/exhaustion
  mutated v2 before the upgrade.
- `/tmp/zasp-correlation-routing-final-attempt-red.log` and
  `/tmp/zasp-correlation-routing-final-failed-red.log`: independent final-attempt
  completion failures. The second subtest in the first run was blocked by the
  still-live first lease; the isolated second run establishes its actual failure.
- `/tmp/zasp-correlation-routing-reviewed-core.log`: focused PostgreSQL suite
  passed in32.358s, including final completion, API48/49, round-trip rollback,
  NULL arguments, private/unrelated authority, and release drift rejection.
- `/tmp/zasp-correlation-routing-reviewed-migrations.log`: migration races passed.
- `/tmp/zasp-correlation-routing-exhaustion-controls.log`: all four actual
  in-flight claim/exhaustion positive and negative controls passed in14.653s.

An earlier in-flight test incorrectly treated a successful SQL no-op as mutation:
fixture timestamps were newer than the blocked transaction. That run is withdrawn
as RED evidence. Corrected controls seed work eligible at the old transaction's
start and assert actual attempt, owner, stage, batch and delivery state changes.
Disabling the trigger is confined to disposable negative controls and is never
accepted as healthy release evidence.

## Runtime, CLI and composed verification

The explicit correlation repository constructor declares private immutable v2
capability. Every claim independently pins49 readiness, even if process readiness
is cached. Only an undefined-function error may try the independently pinned
healthy48 acceptance/candidate authority. False readiness, malformed responses,
permission errors, missing49 claim functions and unexpected versions never fall
back. V2 composition selects this constructor; legacy construction is unchanged.

The SQL final-attempt review also exposed existing Go result mismatches. Both the
repository and worker now expect failed/exhausted for retryable or failed
completion at attempt100, preserve the submitted request, and reject wrong state
or error-class responses. Actual PostgreSQL verifies terminal replay through Go.

The composed proof first drains production-created v1 raw and semantic jobs on48.
It then runs the real migration runner, replays the old acceptance unchanged, and
ingests fresh OTLP/kernel-shaped events. The former fixture UPDATE selecting v2
was removed. Registered workers claim the producer's v2 work and write actual
local PostgreSQL snapshots, S3 receipts, OpenSearch and authenticated TLS Neo4j
effects. Natural lease expiry, frozen Strong recovery and new Probable conflict
pass. The full installed-Chrome suite also passes on49 with exact cleanup.
Sensor enrollment and external sources remain declared fixtures, not live
producer attestation, live IAM or managed-provider deployment evidence.

Additional evidence:

- `/tmp/zasp-correlation-routing-repository-red.log`: repository routing contract
  failed before capability wiring; the race-checked successor passes.
- `/tmp/zasp-correlation-routing-repository-postgres.log`: actual healthy48
  fallback,49 v1/v2 claiming, legacy exclusion and per-poll drift rejection pass.
- `/tmp/zasp-correlation-routing-finish-repository-red.log` and
  `/tmp/zasp-correlation-routing-finish-worker-red.log`: result mismatches
  reproduced before correction.
- `/tmp/zasp-correlation-routing-runtime-final-races.log`: full runtimeevent and
  worker race suites pass.
- `/tmp/zasp-correlation-routing-all-focused-races.log`: all focused routing
  PostgreSQL races pass in49.537s, including Go terminal replay.
- `/tmp/zasp-correlation-routing-fresh-producer-full.log`: fresh production-created
  v2 runtime proof and complete browser suite pass with cleanup. This predates
  the final CLI/renderer adjustment; its full successor rerun is still required.
- `/tmp/zasp-correlation-routing-cli-actual.log`: actual CLI up-to48, activation49,
  repeated49 registration/readiness, refusal to downgrade49 and empty rollback
  pass. Historical48 security checks remain48 fixtures by explicit selection.
- `/tmp/zasp-correlation-routing-migration-command-red.log`: renderer accepted a
  hostile executable despite correct args. It now requires one migration
  container with exactly `/bin/sh -ec` and the selected migration arguments.
- `/tmp/zasp-correlation-routing-publish-verify.log`: full final verification
  passes1,188 UI tests across196 files, typecheck, lint, build, source/compiled
  imports and all728 ledger rows.
- `/tmp/zasp-correlation-routing-publish-source-gate.log`: final source release
  gate passes. Built-image signatures/scans and deployment gates remain external.
- `/tmp/zasp-correlation-routing-publish-migration-races.log`: full migration CLI
  races pass in73.782s and migration package races in1.397s.
- `/tmp/zasp-correlation-routing-staged-secrets.log`: staged diff scan passes.

- `/tmp/zasp-correlation-routing-publish-combined-full.log`: final complete
  composition rerun passes using the explicit up-to48 CLI, real48-to49 runner,
  fresh production-created v2 jobs, full installed-Chrome suite and cleanup.
  Exit status is0. No fixture stage-version update is used for that v2 proof.

Independent final staged review found no blocking defect, conditional on the
final combined rerun passing and its evidence being recorded before publication.
That condition is now met. Publication and hosted CI remain pending; this is not
approval of the external production-deployment gates or original-task closure.

## Required deployment order

The migration hook runs before workload replacement, so old API binaries must
not be left serving when49 is activated. For an existing48 installation:

1. Build and verify one immutable compatible release. Render with
   `renderRelease(config, { schemaVersion: 48 })`, or the matching chart value
   `schema.expectedVersion=48`. Its hook runs `agentsec-migrate up-to-48`, which
   cannot activate49 and refuses an already49 database.
2. Complete that API and v2 worker rollout. Verify all serving API replicas use
   the compatible digest and pass48 readiness. Verify v1 backlog processing and
   candidate authority. A rendered manifest alone is not proof of this step.
3. Activate49 using the same verified compatible release with the default49
   rendering. Its hook runs `agentsec-migrate up`. Verify exact49 readiness,
   fresh ingestion, queue processing and tenant-scoped UI results.

The renderer binds the chosen schema, API annotation/env and exact migration
command. Its default49 validator rejects a48 manifest unless the caller explicitly
requests48 staging. The final staging release gate still requires49; intermediate
compatibility staging is not credited as the completed deployment.
Do not downgrade a database retaining v2 work or candidate snapshots, delete
evidence to permit rollback, or return to an API binary limited to48 after
activation. Live rollout and managed-provider evidence remain external gates.

No task or milestone closes from these prerequisites. Full original sandbox/
container/cgroup/process lineage acceptance, mixed-evidence UI acceptance and
production deployment still require verification. Counts are unchanged.
