# P4B fix1 independent source review

## Verdict

Spec: the frozen fix1 source addresses both original P4B findings. Source review passes; local P4B acceptance remains pending final installed evidence and confirmation that the frozen source did not change.

Quality: no new Critical, Important, or Minor defect identified in the reviewed fix-only overlay. This is a source-only verdict, not a completed integration gate, merge approval, or production-readiness claim.

The Superpowers requesting-code-review checklist informed this independent spec, authority, test, and quality review. No source, index, branch, or original review artifact was changed. This report is the only review write. No nested agents or long test reruns were used.

## Exact scope and verification

Reviewed `p4b-fix1-source-review.diff` against `p4b-fix1-baseline.json`, with the fix1 handoff and static source-review report, the approved design/execution plan, and the original P4B review. The whole dirty checkout and `HEAD~1` were not used as the change boundary. All packet paths below are relative to `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`.

Independently checked, then rechecked at report creation:

- All 11 changed-file SHA-256 values match `p4b-fix1-source-review-hashes.json`.
- All five packet hashes match: baseline, source manifest, scoped diff, static report, and capture script.
- All 204 non-null historical SQL records from the original P4B baseline remain byte-equal: 202 migration-directory SQL files plus two tenant-RLS SQL files.
- `git apply --reverse --check p4b-fix1-source-review.diff` exits zero. This is a non-mutating overlay consistency check.
- Hash manifest SHA-256: `c4d668541848b19466859f13320f748131db69c99eff1d33ff69867a29491c9b`.
- Source manifest SHA-256: `47436fc0380b1fd04787855b7c4ba4d79175ae153cc676be415c0013c4bcde1f`.
- Scoped diff SHA-256: `976cea0c595b5b5b8f3f0df06196153812bc905a56e3d3bf0f3136badc00ceed`.
- SQL72 SHA-256: `3e20d5ea41a47ae8e03540ecd08264748faea58fedf78544cc5f334e23e19d8c`; compiled independent catalog pin: `b8b6cca0dd01e2b6a5ed03917def976434f37746a93413ad5a42bc3917b6a253`.

## Original finding dispositions

### P1: asymmetric retained/72 generation ownership

Addressed in source. In `services/platform/migrations/sql/0072_production_temporal_discovery.up.sql`, `active_owners` and `capacity_available` (422-438) give both families the same scoped integration/provider exclusion. `try_capacity_lock` (441-446) uses the historical quota acquisition lock and refuses non-current transaction isolation. The retained job mutation guard (478-494) rechecks capacity before granting a lease. The generation guard (496-523) checks the same ownership before an INSERT can grant input authority, including an INSERT that would otherwise encounter an existing reservation. The 72 preparation path (556-575) checks under the same lock, and the pre-IO guard (583-587) requires current authority plus current durable ownership.

This closes the original sequence in which 72 prepared generation 1, a retained caller obtained generation 2, and the retained application invalidated the already-dispatched 72 work. The reverse acquisition order is also excluded. Lease expiry or terminal bookkeeping does not erase an unresolved reservation.

The fix also handles retry and cutover details that a claim-only check would miss. Private FORCE-RLS `retained_dispatches` (357-374) binds scope, job, attempt, sync, integration, provider, generation, snapshot, worker, token digest, and checkpoint. Repeated preparation in the same attempt is denied. A later attempt needs an exact recorded safe completion and advancing checkpoint (449-456, 480-483, 514-519). A generation prepared before72 without this evidence is quarantined, including while its old lease is live. That is a deliberate pending-outcome boundary, not an invented successful retry or newly minted lease protocol.

Regression evidence inspected: `TestTemporalDiscoverySymmetricOwnershipPostgres`, `RetainedPreparationPostgres`, `PreexistingPreparationPostgres`, `RetainedSafeResumePostgres`, and both actual collector acquisition orders. The installed collector child checks credential/provider/storage counts at the blocked boundary and requires nonempty typed application plus succeeded completion before ACK. The parent checks persisted syncs, snapshots, projections, original deadline, and released ownership. A nil processor result alone is not counted as success.

### P2: missing shared organization discovery quota

Addressed in source. The active-owner set (422-431) includes live pre-generation retained claims, unresolved retained generations after lease expiry, and72 reservations, without counting a retained job twice for both claim and generation. `capacity_available` (434-438) reads the existing organization quota or default4, excludes the same scoped job for safe continuation, and also enforces resource ownership. New acquisition and mutation use the existing serialized quota boundary. A denied72 preparation receives an immutable advancing no-IO wait receipt (559-566), not a generation or page-effect grant.

The SQL13 bulk compatibility change (459-475) filters in both historical eligibility clauses before organization/job LIMITs; its row trigger rechecks at mutation. This prevents an oldest blocked tenant from hiding a later eligible tenant. SQL10 discovery access is not restored, and its retained runtime claimant remains unchanged.

Regression evidence inspected: configured quota1 across distinct integrations and both owner orders; default4; live retained preparation; unresolved ownership; independent-tenant limit1 bulk progress using repeated IDs across tenants; replica lock contention, rollback without leaked authority, and subsequent committed-owner exclusion; verified snapshot release followed by successful collection. This is P4B discovery quota enforcement, not a P4C deferral.

## Fix-introduced surface

No new actionable finding was identified in these checks:

- Catalog handoff is restricted to the named SQL13 bulk claimant/fingerprint and SQL60 identity helper (468-475, 877-894), plus the existing narrow51 handoff. Saved original definitions remain immutable and pinned. Readiness still compares live owner/ACL attributes for every saved entry (129-130). The independent72 fingerprint includes actual replacement definitions, saved originals, private helpers, quota/checkpoint table shape, RLS, constraints, indexes and triggers (846-913). No historical expected pin or historical SQL file is refreshed. Installed authority tests include replacement-body/security drift, disabled guards, saved-definition mutation, unrelated function drift, quota ACL drift and private mapping permissions.
- The retained claim/apply repository selects72 only through current retained readiness, and present-invalid72 fails closed (`services/platform/apiserver/discovery_execution_repository.go:177`, `:483`). Direct obsolete SQL13 delivery can still raise23502 when its guarded UPDATE returns no row; the supported wrapper returns typed busy. The statement rolls back, and there is no broad23502-to-busy mapping. This remains explicit temporary P9 compatibility debt.
- Configuration hydration canonicalizes the validated JSON object without dropping fields (`discovery_execution_repository.go:233`). Unknown, invalid-type and mixed-provider configuration still reaches strict rejection before IO. The change does not broaden credential content.
- The private relationship normalizer validates raw schema/types/IDs/duplicates before mapping, preserves the existing exact scoped integration/source/native edge ID including removed rows, and uses the existing integration-scoped helper for a new edge (376-393). It does not duplicate shared entities or reparent a foreign connector row. The retained apply wrapper binds mapping to the exact prepared lease/attempt/generation/snapshot and atomically persists raw request digest plus normalized relationships (395-412). The72 complete receipt stores the normalized candidate while retaining the raw replay digest (603-629). Both replay paths return their recorded result without recomputing identity from later mutable inventory.
- Identity evidence includes the same-account, different-integration fixture in both quota orders, shared entity IDs, separate stored edges, historical noncanonical edge preservation, replay after controlled/restored live-ID mutation, generated-ID collision refusal, and connector-local removal through an explicit empty installed domain snapshot. Four-provider mapping is SQL/helper evidence; it is not four live-provider integrations. The source rejects ambiguous existing native mappings, but the focused mapping test does not directly construct that ambiguity or every cross-scope permutation. No concrete escape was found in the scoped predicates.

## Evidence limits and acceptance boundary

The inspected `p4b-fix1-cutover-identity-green.log` ends in package PASS215.611s. It covers preexisting preparation quarantine, both quota collector/identity/removal cases, safe resume, mapping validation and installed authority. The corrected focused race log reports API2.180s, worker2.856s and orchestration1.651s. Its installed-only children skip without their owned PostgreSQL parent; those skips are not integration passes. Earlier four-collector evidence predates the final cutover amendment, so the complete current-source rerun still matters.

At this review checkpoint, session91184 and `p4b-fix1-final-installed.log` are still running. The reviewed command is:

```text
go test ./agentsec-migrate -run '^TestTemporalDiscovery.*Postgres$' -count=1 -timeout 45m -v
```

No package-level final result was available when this verdict was written. Progress PASS lines do not establish completion. Acceptance requires its final result, the final evidence/hash packet, normal owned-process cleanup, and another comparison against all frozen source hashes. Changed source requires renewed review of the delta.

The overbroad race command failed the API package at241.022s after a sensor child build requested module updates and the package timed out in NaturalRecovery. It remains unresolved full-suite/P8 evidence debt. This review does not label it a proven product deadlock or an external blocker, and does not turn cleanup into a passing run.

The original17-case731.887s installed run followed the original lifecycle/starter amendments; the267-page663.984s cold-continuation run preceded them. Both predate fix1 source. Original final-source isolation and controlled real-Temporal starter evidence retain their narrower historical scope. The original unexplained checkpoint40 `outcome_unknown` remains unexplained; none of the diagnosed fix1 fixture failures supplies its cause. Cold artifact O(n²) rereading remains disclosed scale debt.

P4C/P4D, full API-root P8, P9 retirement/backlog-equivalence, and live Stytch/OpenFGA/provider gates remain mandatory. In particular, unresolved retained preparation must have an explicit P4D/P9 recovery/cutover disposition; it cannot be silently dropped to reclaim capacity. This review grants no deployed authorization or production acceptance.
