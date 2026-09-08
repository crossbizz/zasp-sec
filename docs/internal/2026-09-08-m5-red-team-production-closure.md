# M5 Red Team production closure

Status: audit and implementation in progress. No M5 promotions yet.

The original M5-01 through M5-22 requirements remain in scope. Existing
production routes and worker adapters are not sufficient evidence for the
whole task group; each original deliverable still needs its own verification.

The first audit identified these gaps:

- Red Team browser API responses are schema/ETag checked but are not all bound
  to the requested resource, definition version, or mutation intent.
- The UI creates new mutation identities on retry, permits competing actions,
  and does not disable writes when its source query becomes stale.
- The production target predicate checks discovery freshness and target
  configuration, but does not itself check the authoritative environment
  class. Non-production safety labels supplied by a caller are not sufficient.
- The target adapter receives a run ID but its database resolver currently
  resolves only scope and target. Run/lease/category authorization must be
  checked before resolving credentials or invoking a target.
- Capability-derived pack recommendations exist in the legacy component, not
  yet in the verified production create flow.

Execution keeps API/UI request recovery separate from the database and target
execution authority. Use Superpowers test-first regressions, independent
review, actual PostgreSQL and composed-worker/browser verification. Do not
promote any M5 task based on a fixture or by weakening a safety check.

The preceding M3-52d slice passed both push/PR CI and merged through PR #9 as
`c082b80cf5612bd201cdd3104433c6fc954d8745`; main CI `34290871149` passed. Its
pre-push scanner warnings were numeric false positives: a GitHub CI run ID and
two synthetic product-ID fragments, not personal or payment data.

The Red Team browser API now binds all six resource-read/mutation methods to
the exact request identity and intent. Seventeen valid-schema mismatches were
accepted before the fix; the new suite now passes 28 checks, including stored
receipt replay and leased cancellation without a false terminal claim.
Independent review approved compatibility with the SQL receipt semantics.
Existing API/UI checks and type-check also pass. This is a bounded improvement,
not completion of M5 or its target-safety authority.

## Schema 37 admission safety

The actual PostgreSQL regression first accepted a fresh target after its
authoritative environment changed to production. The guarded forward migration
now rejects that target. Create/update definition, new run admission, and worker
claim also require an exact match to the authoritative environment and an
active, unexpired operator registration in the existing scoped credential
registry. Discovery metadata and caller-supplied credential labels cannot grant
that authority. Existing migrations are unchanged.

The actual database checks now cover environment mismatch, credential-class
mismatch, revoked/expired credentials, credential-reference drift, and stale
discovery. Registered API and worker principals prove safe creation/queue/claim,
denial after revocation, and an unchanged queued run after a rejected claim.
Rollback restores the exact v36 fingerprint and prior target semantics;
reapplying restores protection. Public EXECUTE drift, helper-body drift, and an
unknown future version fail readiness. Independent review reran the expanded
test under the race detector and approved this bounded change.

The CLI, deployment schema expectation, API readiness ceiling, and combined
test release assertion now target 37. Full CLI verification exposed the
additional central migration-version ceiling; that was updated without relaxing
checksum or future-version rejection. Fresh CLI/migration race verification
passes. All 185 frontend test files (1,015 tests), type-check, lint, production
source/compiled imports, release rendering, build, and 728-row ledger checks
pass. The release-source gate passes while keeping built-image/cloud gates
external. The fresh-build installed-Chrome combined journey passes on schema
37, including actual local runtime queue/archive/index dependencies and all
previous discovery, isolation, security, Attack Lab, recovery, identity, and
restart/reload assertions. The full API race suite passes (265.534 seconds).
An obsolete readiness source assertion was updated from ceiling 36 to 37;
its focused regression and the full suite both passed afterward.

This does not yet prove adapter-time run/lease/category authorization, the
Promptfoo process composition, reliable UI mutation recovery, capability-derived
pack recommendations, or live cloud execution. Those remain required before
promoting M5-01 through M5-22. The authoritative production counts remain
515 available, 152 component-only, 61 blocked/external, and zero missing.

## Next execution regression

The runner currently treats every nonzero Promptfoo process exit as an engine
error. The pinned [Promptfoo 0.121.19 evaluation source](https://github.com/promptfoo/promptfoo/blob/0.121.19/src/node/doEval.ts)
uses exit 100 for a completed evaluation below the pass threshold, after writing
its output. The next process-level test must distinguish that completed failing
security evaluation from a crashed/incomplete engine, while still validating
the exact normalized output. This is an identified integration gap, not a
completed fix or evidence of a passing production Red Team flow.

Inspection of the exact pinned container also confirms that
`/app/node_modules/.bin/promptfoo` does not exist; its package declares
`dist/src/entrypoint.js` as the CLI. A network-isolated actual-image regression
now fails on the first safe evaluation with the existing production runner.
That regression belongs to the next execution slice and is not yet a green
production proof.
