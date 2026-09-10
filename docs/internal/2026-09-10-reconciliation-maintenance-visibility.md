# Reconciliation maintenance visibility

Status: locally verified production visibility change on
`codex/reconciliation-maintenance-monitor`. No original task credit changes.
The ledger remains 535 production-available / 132 component-only / 61 external
gates, covering all 728 original microtasks.

PR 36's evidence-only experiment merged as main `967673f4` after push CI
34515382318 and PR CI 34515440592 passed. Main CI 34516356752 passed.

This change adds actual production visibility into maintenance debt, not cleanup
or an empty-queue shortcut. The API queries only public catalog estimates for two
fixed tables under its existing database role. It does not read customer rows,
grant privileges, change schema/policy, add a global counter, or issue VACUUM.
The production pool samples in fresh autocommit statements; disabled statistics,
missing tables, malformed/null required values and query failures are unavailable.
Globally enabled autovacuum and table overrides both affect the reported flag.

The API lifecycle owns one serial sampler, every 15 seconds with a two-second
deadline. Cached samples expire after 45 seconds using local monotonic age.
Scrapes issue no SQL. Invalid data emits an explicit validity zero and no table
gauges. Shutdown invalidates the cache; old completions cannot replace newer
samples. All labels are fixed, private and independent of tenant cardinality.
Readiness and customer requests do not wait for maintenance success.

Rendered Prometheus rules warn about sustained estimated debt, disabled ordinary
autovacuum, invalid samples, missing sampler metrics and failed/absent targets.
Rule tests execute the actual rendered expressions with checksum-verified
Prometheus 3.14.0. CI pins its Linux archive checksum and runs those tests.
The operator runbook distinguishes estimates from cleanup proof and does not
authorize automatic session termination, slot removal or `VACUUM FULL`.

## Evidence

The startup metric test failed before implementation
(`/tmp/zasp-maintenance-monitor-red.log`). A later shutdown test caught deferred
time evaluation leaving a sample valid after cancellation; the corrected closure
passed `/tmp/zasp-maintenance-monitor-focused-green.log`. This focused race run
also covers stale/failed/foreign samples and actual API-role metadata reads,
absence of customer-table SELECT grants, table overrides, disabled statistics and
missing tables. API package 2.177s; repository package 7.092s.

The alert test first failed because no production rules existed. Its first engine
run then exposed an incorrect test namespace assumption, corrected to the actual
rendered namespace `agentsec`. All seven Prometheus scenarios then passed in
`/tmp/zasp-maintenance-alerts-green.log`, including debt despite advancing vacuum
timestamps and later recovery. These are executable alert semantics, not a check
that YAML contains an expression string.

`/tmp/zasp-maintenance-pinned-snapshot.log` passed in 96.362 seconds. With an
established repeatable-read snapshot held open, the actual API-role repository
observed 20,000 dead tuples after a vacuum timestamp later than retirement.
After releasing the snapshot, it observed a later vacuum and a zero estimate.
No explicit VACUUM or autovacuum tuning was used. This proves retained estimated
debt remains visible despite a recent vacuum. It does not establish a universal
cleanup deadline, concurrent API p95 or physical scan bounds by itself.

Full verification first failed the existing workflow's exact step-count
assertion after adding the required alert gate. The expected command list and
valid fixture now include that gate; the 15 workflow tests passed. Full rerun
`/tmp/zasp-maintenance-monitor-verify-green.log` passed with exit 0, 196 files /
1,179 tests, types, lint, contracts, production build and ledger. The earlier
failed run remains `/tmp/zasp-maintenance-monitor-verify.log`.

Full API race verification passed in 397.503 seconds, exit 0:
`/tmp/zasp-maintenance-monitor-api-full.log`. Ten race-enabled repetitions of the
sampler tests passed in 2.788 seconds, including discarding a late source success
after cancellation and stopping only after its active query ends:
`/tmp/zasp-maintenance-monitor-final-unit.log`. That enabled run also passed the
actual Prometheus exposition parser. CI now executes both rule behavior and
exposition checks using the pinned tool. Browser-harness contracts passed 21 tests
with 2 existing explicit skips; skips are not runtime proof.

Read-only implementation review found no blocking issue and accepted the pinned
snapshot evidence. Full composed Chrome passed with exit 0 in
`/tmp/zasp-maintenance-monitor-chrome.log`, including the new private metric proof,
owned runtime pipeline, existing user workflows and complete cleanup. Local
provider and graph fixture limits remain as declared by that harness; this is
not a live production deployment or a new correlation proof.
The browser harness now toggles ordinary autovacuum only in its owned disposable
database and requires the launched API's private metrics to observe disable and
recovery through the real lifecycle sampler. The original raw I/O and reference
load gates stay open until their own acceptance evidence exists.

Staged secret scanning passed. Privacy review found six medium warnings and no
high findings; every warning was a public CI run identifier, inspected in context.
Final read-only review approved this bounded visibility change after inspecting
the completed logs and final cancellation/CI tests. Push/PR/main CI remain
required before this change is shipped. No performance task credit was granted.
