# Reconciliation under concurrent API load

Status: opt-in local characterization merged through PR 39 as main `8ec83a9b`.
Push CI 34523789643, PR CI 34523836361 and main CI 34524724253 passed.
No task credit changes.
All 728 classifications remain 535 production-available / 132 component-only /
61 externally blocked. Reference-deployment acceptance is still unavailable.

PR 38's actual API-load runner merged as main `2540c7b4` after push CI
34521277124 and PR CI 34521331499 passed. Main CI 34522254378 passed.

The experiment runs the actual compiled CLI and launched product API while
an owned PostgreSQL database retains 100,000 retired lane rows and concurrent
transactions insert/retire 2,000 more rows. It uses existing schema-46 triggers
and the actual API lifecycle reconciler. Queue fixtures are future-available,
then terminal, so they cannot dispatch to external providers. No production
schema, privileges, planner choices or autovacuum policy changes are introduced.
The opt-in database enables `track_functions=pl` only for diagnostic counters.

Run the composed harness with `ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC=1`.
The first test failed because function accounting was disabled; it cleaned up
all owned resources (`/tmp/zasp-reconciliation-concurrent-red.log`). The setting
is now applied only to the harness's newly created loopback PostgreSQL process.

The diagnostic explicitly checks default autovacuum settings and absent table
overrides. After creating the rows, it pins a repeatable-read snapshot and retires
the exact fixture prefix. It runs 400 actual authenticated HTTPS reads over
20 seconds, with 20 requests/second and at most four active requests. At least
10 writer batches must commit inside that measured interval. The private API
maintenance metric must report at least 100,000 estimated dead tuples.

The first run passed all 400 reads, p50 4,035,084 ns, p95 25,387,875 ns,
p99 61,732,500 ns, zero errors, 19 overlapping writer commits and 102,003
estimated dead tuples. Default autovacuum recovered after snapshot release,
the retained post-maintenance physical-work bound passed, and the remaining
browser workflows and cleanup passed. Log:
`/tmp/zasp-reconciliation-concurrent-first.log`.

That run does NOT prove its reported reconciliation call count occurred during
API load. Independent review found the counter's baseline preceded EXPLAIN/CLI
setup and its endpoint followed other work. The printed `actual_claim_calls=21`
is disqualified as an in-window witness; it cannot close the acceptance concern.

The corrected experiment samples counters and API-role statement-start activity
during the load, then selects observations strictly inside the measured interval
with a one-second margin. It requires reported counter growth within that window
and an observed reconciliation statement starting inside the actual interval.
PostgreSQL publishes function statistics asynchronously, so the delta is reported
growth, not an exact execution count. No raw query text or customer data is saved.
The stricter run passed with exit 0 in
`/tmp/zasp-reconciliation-concurrent-strict.log`: all 400 reads succeeded,
p50 4,148,541 ns, p95 31,897,208 ns and p99 63,662,333 ns. Nineteen writer
batches committed inside the measured interval. In-window observations showed
17 published additional claims and an API-role reconciliation statement starting
inside that interval. Estimated debt was 102,000 tuples. The raw plan consumed
4,715 shared hits before recovery, then three hits and zero reads after default
autovacuum recovered. Browser flows and owned cleanup passed. This does not
establish the inherited immediate-retirement 2,048-buffer bound.

Independent review also identified potentially unbounded waits for the snapshot
process to exit. Both success and cleanup waits are now bounded; the strict run
preceded that last fix. The final-code repeat passed with exit 0 in
`/tmp/zasp-reconciliation-concurrent-final.log`: 400 successful reads,
p50 3,797,917 ns, p95 15,499,125 ns, p99 53,807,209 ns, zero errors,
19 overlapping writer commits, 19 in-window published additional claims and
an API-role claim statement starting inside the window. Debt was 102,000;
raw shared hits fell from 4,715 to three, with zero reads, after default vacuum.
All remaining browser flows, API restart and owned cleanup passed.
The tested profile records a dirty working tree based on main `2540c7b4`, not
an attested deployment of the later commit. Full verification passed with
exit 0 in `/tmp/zasp-reconciliation-concurrent-verify.log`, including 196 test
files / 1,179 tests, types, lint, production build, compiled import checks and
the unchanged 728-row ledger.
Harness contracts passed 21 tests with two explicitly gated live-cleanup skips in
`/tmp/zasp-reconciliation-concurrent-contracts.log`. Read-only source review found
no remaining blocking issue, conditional on the post-fix repeat and shipping CI.

After releasing the snapshot, acceptance requires a vacuum timestamp strictly
later than release, zero estimated dead tuples, and an actual raw-plan shared
read-plus-hit count at most 2,048. No manual VACUUM or empty-row/cache-warming
count is issued. SQL steps share a four-minute diagnostic budget, the writer has
a 30-second budget, the snapshot has an independent bounded lifetime, and all
concurrent operations are settled before teardown.

The profile remains the local composed dataset with declared provider fixtures.
It does not establish reference capacity, all-tenant performance, a general
maintenance deadline or immediate post-retirement raw-scan compliance. The
original M8-36b/36 external gates remain open. Required push and PR CI passed;
main CI also passed. The official upstream Superpowers TDD,
verification-before-completion and independent review workflow was followed;
the installed Superpowers plugin is unavailable, so no installed-plugin run is
claimed. Staged secret scanning found no leaks. Privacy scanning reported
14 medium warnings and zero high findings; all contexts were public CI run
identifiers or fixed fixture UUIDs, not personal data.

Read-only sequencing review found no measured dependency that requires another
reconciliation architecture change before isolated runtime candidate-authority
work. That work may proceed while the immediate-retirement raw-work concern and
reference-load gate stay open. This is sequencing, not acceptance of a reduced
maintenance contract. No assertion or production gate is removed or relaxed.
