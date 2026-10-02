# Cleanup process proof passed on the frozen source

The final registered run is `2026-09-20T01-43-46.293Z/`: all seven selected groups passed, with zero failures and zero skips. The strengthened cleanup parent passed in 196.39s. All 1,635 recorded source-file hashes match the final files. See `final-report.md` for exact commands, source hashes, quotas and cleanup evidence.

`TestSecurityAgentExportCleanupProcessPostgres` passed191.38s in the owned network-disabled PostgreSQL container. The retained run is `2026-09-20T01-40-18.100Z/`. Its PostgreSQL process joined normally; the operator removed its exact container and temporary binary directory.

Three artifacts were created through the accepted public API and actual planner/worker process entries: a same-org sibling, a second-Organization artifact, then the cleanup target. Each had a successful conditional PUT, prepared package, immutable version and mounted download. The fixture seeds organizations, scoped identities, durable sessions and registered worker logins. It does not seed export definitions, runs, plans, links, prepared packages or stored objects.

The target's grant obtains a real registered30s read lease through the API login. Public cancellation expires retrieval, but the cleanup process claims nothing and makes no provider request while that read lease is live. The parent waits its actual deadline. A new cleanup process then commits an exact-version DELETE to the persistent SDK transport and exits86 before the acknowledgement. SQL still retains the package and cleanup obligation. The next process cannot steal its60s cleanup lease. No database timestamps are adjusted.

After actual expiry, fresh cleanup processes receive403/AccessDenied and404/NotFound from both DELETE and bounded version-pinned GET. Their real runtime retry commits retain accounting and set30s deadlines, which the parent waits. Only the final typed404/NoSuchVersion on GET lets the runtime confirm deletion and clear the exact target. One physical deletion, one deletion audit, zero cleanup PUTs. The next cleanup tick is a no-op.

Both protected artifacts retain their exact object bodies, metadata and versions. Their job/link/run/plan/provider-accounting rows stay byte-for-byte equal as JSON readbacks. Cross-org API probes in both directions fail before provider access. Final-candidate assertions also re-download the protected artifacts after target cleanup, check the precise retained-byte decrement and require per-process claim/retry/confirmation counts.

## RED and wiring failures are separate

The focused SDK taxonomy test first used an intentionally wrong generic404 fixture code, `NoSuchVersion`. The real cleanup driver accepted it as confirmed absence, so `TestSecurityAgentExportCleanupResponseTaxonomy/generic404` failed:

```text
generic404 classified as confirmed absence: <nil>
FAIL .../agentsec-worker 1.193s
```

Changing only the new fixture's generic response code to `NotFound` made all three cases pass1.238s. Production classification wasn't changed. Before that RED, macOS's symlinked temp root needed canonicalization for the existing persistent-store safety checks; that was test wiring, not a behavioral result.

The first process attempt created and downloaded the first artifact, then failed because the new second-org environment-control request omitted the required `action_key:"*"`. It returned400. The corrected request uses the real public contract; this is also a wiring failure, not a product defect. Its evidence is `2026-09-20T01-39-06.555Z/`.

## Final checks passed

The targeted native race group passed17 top-level tests, zero failures and zero skips: the new SDK taxonomy, both cleanup driver tests, read-only reconciliation tests and persistent-store tests. `native-race.log/.json` retain the result and exact command. Times: worker2.818s, S3 driver1.434s, persistent store3.875s.

The final registered batch passed cleanup, public A-H restart, export lifecycle/authority/stopped settlement, browser-origin compliance grant lifecycle and compliance polling. It used fresh Linux arm64 binaries built offline with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`; full source and binary hashes are in its timestamped `run.json`. Each run has a separate evidence directory to avoid overwriting another run's summary.

Current installed/compiled58 checksum `5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985`, fingerprint `8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f`.

Only the two new allocated test files and this evidence directory were written. Existing tests, product code, SQL, pins and ledger are untouched. No staging, commit or push. This proves controlled local behavior, not live AWS, deployed rollout or browser-native saving.
