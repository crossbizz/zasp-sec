# Candidate grouped UI verification, 2026-09-17

The previous conversational turn only described batching, so it was no progress
toward implementation. This continuation revalidated both worktree heads and the
empty indexes before transferring the independently reviewed three-file repair.

Recovery HEAD: ecc047ee2e90c36ec702ade129a2b08eae0a7a1a.
Candidate HEAD: 8733b16f8d939d38a8157dd2519e57fc6f630542.
No commit, push, deployment or original-task promotion occurred.

## Reviewed repair transferred

The frozen candidate-ui-contract-patch SHA256 was rechecked:
50291ee2d23d1b597386cbbf1c459f3ad246c2ad20a068a77ade4e564d8b6588.

Only README.md, app/quality/m7a-api-builder-batch-contract.test.ts and
scripts/owned-browser-postgres.test.mjs were transferred with apply_patch.
Exact resulting git blobs match recovery:
- README: a0cb1c789f415bf5988185deb6b8e03bac0b2884
- UI contract: a8dd750767254b09ba924f48192c957e5847e118
- PostgreSQL test: e17cf255d450a9f31a2193de07f8dcd72a48157e

This is the previously independently approved test/docs repair. No product
behavior changed. git diff --check passed after transfer.

## Fresh grouped results

Pinned Node22.23.1, offline npm configuration, candidate working directory:
- Full Vitest run52061 exited0: 2001 passed,0 failed,0 pending.
  JSON: /private/tmp/zasp-schema55-candidate-tests.47H9Oq/ui-full-repaired.json
  SHA256:80eecac8b3dca1a6c6f0befb9f845e56a31dfc71f804e521fdc51a05282a2240.
- npm run lint89696 exited0, including the lint-scope test and full ESLint.
- implementation-status-check exited0:728 rows,534 production-available,
  133 component-only,61 blocked/external,0 missing.

These are local source/component checks, not live production acceptance.

## Remaining source-harness failures

Earlier grouped Node batch39326 exited1:88 tests,74 pass,12 fail,2 skipped.
The skipped opt-in runtime/container SIGTERM proofs are not passes.
Staging gate still expects migration54 and rejects55; it needs explicit55
positive/negative rollout coverage, not only a changed latest-version literal.
Simulation/audit source extraction contexts predate existingTestMountedMode.
A blanket Docker source prohibition conflicts with the accepted owned cached
container implementation; any correction must retain ownership, pull and
network controls.

Fresh focused cleanup reproduction exited1 with all7 subcases failing (8 Node
failures including parent). The actual function was then evaluated in memory,
without starting processes or touching files:
- Without mountedRuntimeProofs: ReferenceError after checkpoint.
- With mountedRuntimeProofs=[]: checkpoint, redteam, dependencies and files
  callbacks complete.
The old test VM omits that binding. A repair must also exercise nonempty mounted
proofs and failed joins, retaining every original cleanup/error/root assertion.
No harness test correction was made in this continuation.

Full candidate review, remaining gates, fresh approved advisory evidence,
publication/CI and real deployment/provider/load proof remain open. The stale
README blanket explanation/export-hidden sentence also remains a review item.
