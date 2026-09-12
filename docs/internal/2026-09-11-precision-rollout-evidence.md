# Release51 consumer phase, implementation in progress

The chart and rendered-resource validators now accept schema51 with
sessionSearchPhase=precision-consumers or precision-intake. Schemas48/49 compatibility and schema50
backfill/query retain their existing contracts. Default deployment remains49.

The new phase pins intake to runtime-event-v1; outbox/coordinator select the
dual-version path. Archive2/correlation4/projection3/complete3 drain their allowed
historical and precise work. The separate target2 index deployment selects
index2, while the original target1 index deployment stays on index1. API queries
target2. This phase is intended after verified schema50 query cutover, not as
proof that cutover or provider catch-up has happened.

The rendered-resource test checks each selected environment value and mutates it
to prove validator refusal. V2 intake is rejected in this phase. An additional
test caught historical phases accepting injected V2 selectors; those are now
rejected. Independent review then found historical phases still accepted
schema51-only archive/projection/completion stage versions. Added mutation tests
reproduced that gap; all phases now pin their expected stage versions. The final
combined release/session contract run passed all 45 tests in 9.193s. Scoped
rereview approved the correction and repeated five render tests in 2.102s.

The separate precision-intake phase changes only intake to runtime-event-v2.
A rendered-resource equality test verifies every other resource stays identical
to precision-consumers. Old-reader mutations and schema50/intake selection are
rejected. TDD first reproduced the unsupported phase; the combined release/session
contracts then passed47/47 in9.712s. Independent review found no issues and
repeated6/6 session-search render tests in2.859s.

Before allowing live V2 intake/source activation,
the rollout needs actual ready/current consumers, no old coordinator replicas,
provider checkpoints, and explicit source configuration. A manifest alone does
not prove these conditions. Mixed old-pod readiness during the schema51 hook is
supported by retained compatibility bridges and a same-instance API/HTTP upgrade
regression, rerun on the new semantic pin with actualPG race PASS7.501s. NOWAIT
migration refusal under traffic is safe failure, not uninterrupted-availability
proof. The staging latest-schema gate was unresolved at this checkpoint.
Later root verification65788 and13612 passed the explicit compatibility/forward
chart gate and all94 release tests. That closes source/render validation, not
the complete live rollout, old-consumer drainage or production provenance gates.

The current schema51 draft routes first-committed OTLP/runtime-event-v1 batches
to1/1/3/2/2 using persisted source/schema identity. Historical accepted tuples
stay unchanged. Installing51 activates this routing even while intake remainsV1;
old correlation/project/complete readers leave the new work queued until upgraded.
Down51 refuses pending, retryable or leased OTLP3/2/2 work, including historical
rows, because the schema50 manifests cannot drain it. Completed50-compatible
evidence may survive rollback. This is not a zero-downtime claim.

The new semantic pin is f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd.
Its scoped actual PostgreSQL tests passed42.955s; full actualPG precision races
passed384.915s on this pin. The final combined cached-body/post-wait test
strengthening passed13.776s without changing SQL.
Independent SQL review found no blocking issues and repeated migration races
in1.428s. This does not approve the unresolved provider flow.
The first provider run on this pin failed at semantic
correlation after archive/index, so fresh bound-provider proof remains open.
Provider tests must not relabel rows or count unbound precise evidence as bound proof.

The first provider failure was traced to pending sensor identity fixtures; the
existing harness uses declared active identities. After correcting that setup,
provider80945 passed on the same SQL pin with owned cleanup. It exercised fresh
semantic and precise worker tuples, bound Strong and unattributed events, provider
response loss/replay, target2 checkpoints and API freshness. The strengthened
per-event API/OpenSearch sandbox-field run41328 and independent proof review are
pending. This does not prove real sensor enrollment or live customer deployment.

No deployment, push or original task credit.

The release source gate now renders and validates all six supported combinations:
48/49 compatibility,50 backfill/query and51 precision-consumers/precision-intake.
Its returned coverage records the schema job read from each actual render and
rejects missing/mismatched jobs. The new assertion first failed on missing
coverage in7.406s. Full release-gate tests then passed3/3 in15.161s, including
the existing SBOM, license, secret and runbook checks. Scoped review found no
issues and independently repeated3/3 tests in13.824s.
This checks source artifacts only and does not authorize deployment or resolve
the separate staging latest-schema/activation gate.
