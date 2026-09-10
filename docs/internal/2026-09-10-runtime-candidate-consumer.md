# Consuming frozen runtime candidates

Status: consumer-only change merged through PR 41 as main `4f454ade`.
Implementation `7aba535d` passed push CI 34535065881 and PR CI 34535110848;
main CI 34536010806 passed. Executor work continues separately.
The authority foundation shipped through PR 40, commit `cd22a99e`; push CI
34532351627 and PR CI 34532402341 passed. It merged as main `612f12d3`;
main CI 34533327507 passed.

The full original scope remains intact. All 728 ledger rows retain their current
classification: 535 production-available, 132 component-only, 61 externally
blocked. M3-46, M3-47 and M7-07 remain incomplete. No production v2 producer or
new attribution path is enabled by this draft.

## Boundary being implemented

The private correlation worker must submit its exact current lease, worker/token,
verified index receipt bytes and archived event bytes to schema 47. The repository
validates those inputs before querying. It must not re-encode the index receipt
and call the result proof of the stored object.

The response is a closed hex envelope around at most 1 MiB of frozen snapshot
bytes. Its dedicated bound must not increase the shared 16 KiB control-response
limit. Scope, batch, generation, archive/index digests, enrollment domain,
five-minute selection window and each candidate occurrence must validate. Unknown,
duplicate, case-variant or null fields, invalid identities/lineage/time, duplicate
occurrences and overflow must fail closed. The nullable runtime anchor is allowed
only where the frozen domain and empty candidate set permit it.

The returned snapshot has private fields and defensive slice accessors. V2
correlation will bind its digest to results and receipts; it must not accept an
arbitrary caller candidate list. Existing v1 receipt bytes and in-flight jobs must
remain executable unchanged. Qualified runtime evidence can produce Strong, never
Exact, and competing identities must remain Probable/Unattributed with unknown
authoritative IDs. Sandbox/container/cgroup/process requirements are not removed.

## Evidence so far

`/tmp/zasp-runtime-candidate-consumer-red.log` failed first because the repository
freeze method and exact SQL call were missing. The first implementation passed
focused race tests in 1.754 seconds in
`/tmp/zasp-runtime-candidate-consumer-first.log`: exact 12-argument binding,
original snapshot bytes, defensive copies, private serialization, hostile
envelopes, changed scope/generation/digests/window, invalid anchor/ordinal,
duplicate occurrence and out-of-window or foreign qualified lineage rejection.
These tests use a declared database response stub, not actual PostgreSQL proof.

Input rejection before SQL and the exact 1 MiB boundary now pass. Wrapped
overflow/denial/lost-lease/unknown-outcome errors pass through the actual
`PostgresJSONDatabase` adapter with fixed sanitized errors; that check uses
declared driver fault injection, not a live server fault. Actual schema-47
freeze/replay through the registered correlation repository passed in 10.619
seconds, including own-batch, unpaired, late-conflict and historical replay cases.
The extended adapter run passed in 9.734 seconds.

The delayed-response test failed first for both cancellation and lease expiry in
`/tmp/zasp-runtime-candidate-response-freshness-red.log`. A final context/lease
check after decoding now rejects those responses. Full runtime-event race tests
passed in 3.534 seconds in `/tmp/zasp-runtime-candidate-consumer-full.log`.
Independent read-only review found no concrete blocker in this prerequisite.
`ValidFor` is explicitly historical binding, never current execution authority.

The final full candidate PostgreSQL race selection passed in 26.335 seconds in
`/tmp/zasp-runtime-candidate-consumer-postgres-final.log` after that correction.

V2 pure correlation and canonical receipts are now implemented, still without
producer or executor activation. Missing algorithm and receipt-field tests failed
first in `/tmp/zasp-frozen-correlation-red.log` and
`/tmp/zasp-frozen-receipt-red.log`. Full race suites passed: correlation 1.749
seconds, runtime-event 3.830 seconds, worker 8.399 seconds in
`/tmp/zasp-frozen-correlation-receipt-worker.log`.

Only repository-decoded, exactly bound snapshots provide cross-batch candidates.
Qualified domain and inclusive five-minute matching reject process/start and
cgroup contradictions before identity deduplication. Unique identities are Strong,
competing identities are Probable with unknown authoritative IDs, and explicit
semantic IDs remain Exact. Arbitrary candidate lists are rejected. V2 digests bind
the original snapshot digest even when two snapshots yield equal results.
The versioned receipt requires that digest and rejects schema/field confusion.
An independent literal-wire test preserves existing v1 bytes. Independent review
found no concrete blocker in these pure consumers, with executor fencing and
crash/replay proof still required. This Kubernetes-container profile does not close
the original sandbox/container/cgroup/process scope by itself.

The actual PostgreSQL freeze/replay fixture now also runs the pure v2 correlator
and receipt round trip. It proves semantic Exact, qualified unique Strong,
competing Probable with unknown IDs, and identical result digest/receipt bytes
after late admission and source/anchor revocation. It passed in 9.681 seconds in
`/tmp/zasp-frozen-correlation-postgres.log`. Graph/S3 writes and crash recovery are
not part of that fixture.

Full `npm run verify` passed in `/tmp/zasp-frozen-candidate-ui-verify.log`:
196 UI test files, 1,179 tests, typecheck, lint, source/compiled import checks,
release contracts, runnable build and the unchanged 728-row ledger.

All platform packages compile. Staged gitleaks found no secrets in
`/tmp/zasp-frozen-candidate-secrets.log`. The privacy scan reported zero high
findings and 25 medium numeric-pattern matches; every flagged line was inspected.
They are public CI run IDs and fixed synthetic lineage UUIDs, not personal data.
No suppression or scan bypass was used. Final independent review permits this
consumer-only change after the remaining release gate and required CI pass.
The full source release gate subsequently passed in
`/tmp/zasp-frozen-candidate-release-gate.log`, including CLI races and dependency
checks. Built-image scan/signature, remote checks and live provider/DNS/TLS gates
are separate. PR/main checks are still pending at this pre-push checkpoint.

Next integrate production executor composition,
compatible claim dispatch, sensor lineage emission and mixed-evidence browser
acceptance. The policy supersession characterization from PR 40 remains open;
neither a passing retry nor this repository work proves it fixed.

Superpowers is unavailable as an installed skill. Its previously disclosed
official upstream test-first, fresh-verification and independent-review workflow
continues to apply. No component test earns original-task completion by itself.
