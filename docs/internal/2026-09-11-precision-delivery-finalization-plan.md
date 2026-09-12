# Fresh precision delivery and release plan

Continue the original728-task scope. This plan closes the missing middle between
verified HTTP/recovery and precise stage execution; it does not redefine launch.
Use Superpowers TDD and independent review for each bounded deliverable.

## Delivery authority and old/new coexistence

1. Extend unpublished51 with an explicit runtime outbox claim for dual-version
   publishers. Old claims must leave V2 pending, expired and exhausted work
   untouched, including cached predecessor mutation bodies. Keep other topics,
   fairness, recovery holds, final-attempt completion and immutable replay.
   Bind full51 readiness before and after waits. Update grants, all relevant
   trigger/function fingerprints, lock set and exact rollback restoration.
   Use actual registered PostgreSQL tests, not disabled guards or extra grants.
2. Add explicit precise outbox construction in Go. Only that path admits V1/V2
   runtime payloads under fresh51; preserve old discovery/runtime decoding and
   canonical queue authority bytes. Wire the production composition selection.
3. Add explicit precise queue coordinator and repository selection. Preserve
   pipeline_version15, payload version15 and runtime/v15 artifact keys. Require
   fresh precision authority on claim/heartbeat/release/ack; retain original
   delivery scope/generation/digest/lease checks. Decide and test SQL protection
   against old delivery mutations, not just new Go readiness calls.

The initial Go delivery-readiness regression reproduced an operation query
without readiness. Four operations now check51 first;16 negative cases and full
runtimeevent races passed in5.332s. Independent scoped review found no blocking
issue and repeated targeted races in1.382s. Its duplicate-key test improvement
reverses false/true so permissive last-value decoding cannot pass.

## Prove fresh traffic through all workers

4. Extend the existing combined runtime-only harness after schema50 cutover,
   behind an explicit precision flag requiring both existing runtime-only and
   sandbox-search flags. Preserve historical markers and no-skip assertions.
   Use real owned PG/S3/KMS/SQS/OpenSearch/TLS-Neo4j fixtures. Admit events from
   the precise source normalizer through the client and real ingest handler.
   Do not seed successful stages, snapshots, receipts or checkpoints.
5. Compose archive2/index2/correlation4/projection3/complete3 and precise target2
   search. Assert exact source/process nanoseconds, two starts in one millisecond,
   persisted tuple, immutable receipts/artifacts, atomic session/search completion
   and API freshness only after provider checkpoint. Exercise old/new mixed work,
   tenant denial, stale leases, failed completion rollback, provider-response loss,
   SQS redelivery, HTTP replay, empty DLQ and unchanged historical evidence.
   Fresh sandbox binding requires a supported semantic producer, not relabeled
   V1 correlation2 work. Live Tetragon/spool/cloud attestation remain separate gates.

## Explicit51 rollout, then publication gates

Local steps4-5 checkpoint: final corrected provider run78940 passed on semantic
fingerprint f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd,
with owned cleanup. Independent re-review accepted the added zero-legacy-search
checks and historical target2 document/version preservation. This covers the
bounded local provider proof, not live sensor activation, cloud IAM, composed
browser acceptance or the original task's publication requirements. See the
`2026-09-11-precision-provider-evidence.md` for the repository-retained summary;
the local Superpowers combined-provider-report.md retains intermediate runs.

6. Define and test schema51 phases across production/staging charts and validators:
   schema install, dual-version consumer readiness, target2 catch-up/query, then
   V2 intake/V3 source activation. Prove which prior pod versions remain compatible
   through the schema hook and which must stop or drain first. Keep schemas48/49/50
   contracts explicit. Retained precision evidence must refuse downgrade.
7. Run full root verification, final-pin PostgreSQL regressions and combined
   provider/API/browser acceptance. Review the complete publishable diff and keep
   UI runnable before pushing verified changes to main. Never turn the current
   staging failure into success by only changing the expected schema number.

Evidence boundary: local/provider fixtures establish those integrations only.
Original task rows advance only when their full acceptance and publication
requirements pass. External gates remain recorded, not silently removed.
