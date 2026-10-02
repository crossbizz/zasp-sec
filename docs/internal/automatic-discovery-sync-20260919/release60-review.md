# Release60 runtime review packet

Status: ready for independent review. This file is the implementer's self-review, not an independent acceptance verdict.

Scope: exact scheduler readiness, scheduled-only ID decoding, runtime readiness-before-claim and the registered PostgreSQL replay/completion contract. The accepted release60 SQL, registry and CLI are unchanged.

## What changed

The scheduler constructor and every Ready call now require the exact registered60 checksum/fingerprint. They never consult a predecessor readiness fallback. Discovery worker and projection repositories keep their existing gates. Production scheduler polling uses the existing readiness-gated processor so a drifted repository cannot claim another batch.

Scheduled responses must return the caller's exact sync/job/outbox IDs, even on replay. The general manual decoder is unchanged. Registered admission and completion retain their existing names because release60 replaces those bodies in place. The existing completion decoder accepts the exact stored result without applying a local current-time test.

The affected predecessor-constructor test keeps worker, projection and outbox expectations and security negatives intact. Its scheduler case now refuses predecessor-only releases. The parent authorized that sixth file in the final Task3 brief.

## Checks made

- The real repository admits one occurrence, waits for actual lease expiry, reclaims through another registered connection and preserves all three IDs.
- Receipt generation is0 for initial admission and same-token retry,1 after the first replacement and unchanged on retry,2 after the next real expiry/replacement and unchanged on retry.
- Both previous tokens fail completion; current completion advances exactly once and stores a digest/result. Its lost reply is recovered immediately, after the actual next due instant, after a later claim and after that later occurrence has been admitted. Full tenant state is unchanged by each retry.
- A different completion digest is refused. A completed receipt cannot rebind, including after a registered diagnostic schedule edit returns to the exact original due instant.
- Same-key normalized-ID negatives and different-key provisional-write rollback checks remain. Their full tenant row snapshots include schedules, integrations, receipts, sync/job/outbox, authorities, freshness versions and freshness response.
- A pre-install orphan reaches real lease expiry and prevents60 installation. A blocked predecessor body deliberately resumes after60 installation; its old-first receipt remains unchanged when a current repository attempts stable admission.
- Unknown checksum/fingerprint, wrong principal, revoked scheduled EXECUTE, direct receipt access, tenant/schedule/integration mismatches and stale authority all fail closed.

Final group:51/51 affected apiserver race records,35/35 affected worker race records,289/289 full migration race records,58/58 registered replay/predecessor records and34/34 registered release-cycle records. All have zero failures/skips. Eight final PostgreSQL instances joined normally; no task-owned container remains.

The initial registered RED also exposed a test-only time.Time comparison mistake. Equal timestamps parsed with different location representations compared unequal using ==. That assertion now uses Time.Equal and checks every other field separately; no product behavior was changed for that test artifact.

## Review inputs

Scoped delta: `.superpowers/sdd/2026-09-19-automatic-discovery-schedule-replay-plan/task-3-review.diff`
SHA256: `d67cae60c9865d66a406b22af901e35d619bb456c07081075347289dab5e8ad9`

Evidence: `docs/internal/automatic-discovery-sync-20260919/release60-replay-green.log`
SHA256: `1cde148d7d071b486e9047d5c145babbdf3ef7b6bef88f92fcf6efa63a20aae0`

The diff is against the six files' pre-Task3 content, with inherited dirty work excluded. It reverse-applies cleanly. The sixth baseline was reconstructed by reversing only the parent-authorized scheduler expectation change; the original read was truncated. The other five baselines were retained before edits.

Review SQL fencing, readiness/grants, rollback and Go decoding together with the accepted Task2 final report/fix delta. There is no new SQL edit in this packet. The accepted Task2 rollback/locking matrix is retained, and the exact release-cycle test was rerun on its unchanged, hash-verified binary.

No commit or push occurred. Task4 must still pass the connected browser packet with the actual300-second public cadence. Customer/provider, deployment and external gates remain open.
