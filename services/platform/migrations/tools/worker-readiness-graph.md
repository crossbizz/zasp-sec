# Worker readiness graph source

`build-worker-readiness-graph.mjs` generates the private worker profile's fixed
same-invocation computation of `zasp_temporal77.base67_fingerprint()`. It does
not change historical fingerprint recipes or install expected-value caches.
The emitted installer verifies every expanded original definition and security
frame, and refuses a different input catalog. Direct and drifted calls retain
the original recipe. Expanded values exist only in one SQL statement.

`worker-readiness-regions.mjs` adds three fixed expression regions before the
existing base67 installer changes its precursor: the static rejection predicate
in `temporal68.predecessor_ready`, scalar `temporal68.ready`, and scalar
`temporal78.ready`. The predecessor's leading c/f rejection guards and complete
dynamic 63/64 loop remain outside the replacement. The 78 c/f equality guards
also stay outside. The opaque predecessor call is never hoisted into a shared
CTE, directly or through an intermediate wrapper. NULL behavior is unchanged:
the predecessor IF continues on NULL, 68.ready coalesces false, and 78.ready
retains its nullable AND.

Only explicitly named single-RETURN PL/pgSQL readiness wrappers can become
scalar expression nodes. They must have no other statement, declaration,
exception handler or control flow and must satisfy the same exact frame pins.
Every original is verified before any root mutation. All three roots are saved
before replacement; an existing saved root must match its exact live precursor.
Existing projected68/projected_temporal_profile/projected78 saved-definition
paths retain digest bytes, while the worker fingerprint separately binds live
bodies, owners, ACLs and saved rows. No new function or positive-result cache is
installed. Each separate entry/exit readiness evaluation still recomputes.

The higher catalog leaf checks its exact live definition/owner/ACL and worker
registration before invoking catalog_ready. Drift selects the original recipe
without first executing a replaced catalog body. All fused CTEs remain inside
the selected authority/catalog branch. This is not a native proof of laziness;
paired poison/NULL/role and drift cases are required alongside normal equality.

Input is the JSON artifact from the opt-in application-native
`TestP7OrderedReadinessClosure` test. Its `functions` array contains signature,
schema, name, identity arguments, full definition, prosrc, owner, ACL, language,
volatility, security-definer/strict/parallel flags and configuration. The
`registrations.worker` row supplies the variable worker checksum; the captured
catalog function body supplies its digest. No verifier keys or product rows
belong in this artifact. The initial reviewed input SHA256 is
`720683fb7646085a2ecc226746cb3a71d9dd24d296a6ab2103cbf0d36573bb7c`.
The 14MB evidence artifact is retained separately, not copied into migrations.

Generate new, unused paths:

```sh
node services/platform/migrations/tools/build-worker-readiness-graph.mjs CAPTURE.json OUTPUT.sql MANIFEST.json
```

`--check` compares both existing outputs byte-for-byte without writing.
`--update` replaces generated outputs only if the existing SQL still matches
its manifest hash. Review the complete emitted SQL, not just reproducibility.

Run the grouped generator checks with `ZASP_READINESS_CAPTURE` naming the same
artifact, then run the migration assembly checks. Native acceptance must also
cover original/fused equality in both execution frames, representative live
and saved-catalog drift, parameter NULL/empty behavior, and connected authority
operations under their unchanged deadlines. Reproducibility and source tests
alone are not a SQL parser or native behavioral proof.
