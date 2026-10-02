**Cleanup cannot recover after its signed marker expires: ADDRESSED for the reviewed marker-expiry, replacement-expiry and changed-composition paths.** The fix appends renewal proof, keeps the original target and effect identity, and reconciles an acknowledged replacement without requiring a live removal marker. One new Important recovery restriction remains below. Fix round 1 does not pass.

### Finding checked

Check: the authoritative finding is Important issue 1 in `docs/internal/2026-09-22-temporal-openfga-p3bii-review.md:25`, including unfinished delivery and restart after acknowledgement. The controller's fix1 ruling also requires recovery after replacement-cap expiry and changed current composition.

Check: `services/platform/migrations/sql/0068_production_temporal_executor.cleanup.sql:164` binds renewal to the original source digest and exact stored target; `:168` appends the original target, fresh envelope and unchanged effect identity. The ledger has an immutable trigger at `:26`; `cleanup_marker` checks its sequence, source binding and matching audit at `:33`. The Go facade verifies the fresh envelope against configured keys before SQL at `services/platform/apiserver/security_agent_temporal_executor_repository.go:237`. Expired envelopes still fail.

Check: post-ack completion at `services/platform/migrations/sql/0068_production_temporal_executor.cleanup.sql:116` checks current composition, replacement freshness and exact desired/applied generation without the old marker-expiry condition. Replacement-cap renewal is at `:48`. `services/platform/migrations/sql/0068_production_temporal_executor.delivery.sql:72` detects changed composition/generation or an expiring replacement, requires fresh removal authority, archives the previous delivery, and allocates a later sequence. Historical signed bytes and acknowledgement audits are checked at `:25`; current readback remains mandatory at `:100`.

Check: the shared fixture deactivates the requester at `services/platform/apiserver/security_agent_temporal_executor_postgres_test.go:1552`. New recovery cases reconnect the compensation principal, reject premature completion and expired source reuse, assert unchanged original target bytes, refuse cross-scope renewal, and count exact bundles/revisions/acknowledgements. Marker source/read/ack cases cover applied and partial effects. Replacement-expiry and changed-composition cases cover applied effects only. The signed 25-hour-old source is an explicitly seeded historical fixture, not successful fresh storage of an expired signature (`:1643`).

### New breakage

**Important: a freshly trusted signing key cannot renew an old-key cleanup marker.** `services/platform/migrations/sql/0068_production_temporal_executor.cleanup.sql:164` adds `env->>'key_id' IS DISTINCT FROM t.key_id` to the rejection condition. That pins all future renewals to the original signing identity, even though the Go boundary has already verified the new envelope against the caller's current configured trust set (`services/platform/apiserver/security_agent_temporal_executor_repository.go:237`).

Check, static reproduction: store a valid marker signed by key A; let its five-minute window expire before delivery; restart compensation with a configured, valid key B; sign the same empty removal marker for the same scope, device, credential, sequence and policy version using B, and supply A's original source digest. Go accepts B's valid configured signature. SQL then raises `40001`, `executor cleanup renewal source changed`, solely because B's key ID differs. Replaying A's expired envelope fails at `cleanup.sql:159`; replacing the original source fails the immutable replay check at `:177`; delivery remains blocked at `delivery.sql:70`. If A's private signing material is retired, retries cannot recover.

Check: this is a new equality on the renewal path, not a request to accept an untrusted key or re-verify expired historical proof as current authority. The original source and its digest can stay unchanged, with the fresh configured-key signature retained in the renewal ledger. `policy.GatewayPolicyKeys` supports a configured key set (`services/platform/policy/gateway_cache.go:103`); the current renewal facade does not require that set to contain the original marker's key. The added tests reuse `ordered-key-01` and the original private key at `services/platform/apiserver/security_agent_temporal_executor_postgres_test.go:1694`, so their passing output does not cover this rejection.

Check needed: extend one owned source-expiry recovery case to sign and verify the renewal with a second configured key after reconnecting. Require unchanged original source/effect/history, one renewal on replay, fresh delivery readback/ack and completed cleanup; retain unknown-key and invalid-signature refusal. Remove the old-key dependency through that narrow verified-renewal boundary, without weakening current key verification or rewriting original evidence. No new installation-wide key-management design is required for this case.

Critical: none found. Minor: none introduced by this fix.

### Outside this fix

Check: the previously reported vet failure at `services/platform/apiserver/security_agent_attack_lab_settlement_postgres_test.go:330` is unchanged and non-blocking for this scoped round. No other outside-diff finding was added.

Check: P3C workflow/Activity composition, P7 active OpenFGA enforcement and P10 deployed provider/enforcement/cleanup proof remain gates. These controlled local fixtures do not prove production. Retain P3B-I's supported-predecessor installation evidence.

### Evidence checked

Check: read the full six-file, 641-line fix-only diff in passes against `p3bii-fix1-baseline`, the three binding briefs, original review, fix1 report append and controller ruling. HEAD-wide changes were not reviewed again. Read-only context checks covered the existing composition, effect lock/current-authority path and configured-key verification to resolve risks introduced by these hunks.

Check: read-only `node -e` verification using `fs.readFileSync` and `crypto.createHash('sha256')` compared every manifest before/after file, report, freeze and retained log. Output: `changed=6, logs=121, bad=[]`. Diff SHA256: `c3592763a978c10781ed8de45e370b859ed989937d3261953c25be7f04573e25`. Report SHA256: `db211e28d3cbe14dc3cc5fd6734dc0d7cdc36396149921403f230ff1371da0fe`.

Check: a second read-only Node comparison checked frozen file hashes and historical SQL against both original and fix1 baselines. Output: `frozen=1919, freezeMismatches=0, historical=150, historicalMismatches=0`. The capture script was read, not executed, because it writes manifests.

Check: the report names the final affected command, run from `services/platform`: `go test -vet=off ./apiserver -run '^TestTemporal(Executor(CatalogPostgres|PolicySourcePostgres|CompensationPostgres|LinkedSettlementPostgres|LinkedStopPostgres|CleanupExpiryRecoveryPostgres|CleanupReplacementRecoveryPostgres|SourceSignatureBoundary)|DeliveryWireNullability)$' -count=1 -timeout=20m -v`. Retained `p3bii-fix1-final-postgres.log:121` says `PASS`; `:122` says `653.622s`. Counting its records returned `topLevelPass=9, failSkip=0, joined=16`, each owned PostgreSQL join reporting pg_ctl/server exit 0.

Check: retained marker-expiry group passed 226.15s at `p3bii-fix1-final-postgres.log:37`; replacement recovery passed 262.58s at `:60`. Catalog, policy source, linked settlement/stop, compensation, signature and nullable-wire groups passed too. Read the retained expiry RED tail (`187.446s`), recomposition development tail (`66.623s`) and independent catalog compilation output binding executor pin `be53d9083ba2f32c3d81ce9dc4aeb16e32a822cd3f2358252556ecf8505b9d02`.

Check: no test was rerun. The new finding follows directly from the explicit SQL equality and the verified Go input path; no runtime reproduction is claimed. No source/index edits, git commands, subagents, activation, commits or pushes. Only this report was written.

SPEC: Issues found. The original timed recovery paths now have retained passing evidence, but the new renewal operation depends on indefinite availability of the original signing identity.

QUALITY: Needs fixes. Address the newly introduced trusted-key renewal rejection.

**Fix round: Findings remain open.** One Important fix-only issue: fresh configured-key renewal is rejected after the original signing key changes.
