# Private precise finalizer construction

The new SQL fragment derives a separate precise session finisher from schema50
using checked substitutions. It selects complete-v3, projection-v3 and receipt-v3,
and rejects non-Tetragon/Exact items. Historical functions remain unchanged.
The function is owned by the discovery authority with no PUBLIC or worker grant.

Superpowers evidence:

- Actual PostgreSQL test first failed because the precise authority was absent.
- After implementation, real PostgreSQL18 tests passed. The expanded race run
  exited0 in5.914s, with the test itself taking3.79s.
- Catalog privileges deny coordinator, projection/correlation workers and API;
  a real ungranted worker call returns42501. With a test-only coordinator grant,
  valid V2 requests and V3 claims with V2 predecessors return22023 without
  retaining session events or projection receipts. Historical function bytes
  and schema50 readiness are unchanged.
- Independent review found no issues in this private construction unit.

Successful V3 persistence, execution of the new item-validation branch, replay,
search enqueue compatibility and complete precision migration readiness are
not yet proved. The fragment retains schema50 readiness only as a draft
prerequisite; registration must replace it with the complete precision contract.
No triggers were disabled and no production grants were added. No push or
original microtask credit.

## Item execution and enqueue rejection

The follow-on actual PostgreSQL test now builds projection/receipt V3 with the
real precise codecs. Direct SQL cases supply forged final-source and Exact
items with matching predecessor SHA256, then require the specific precise
item error. An otherwise valid receipt reaches the legacy search insert guard.
Every case proves rollback of completion, session rows, projection receipts
and both search outboxes. No triggers are disabled.

This proves the item-validation branches and transaction rollback, and confirms
the known enqueue obstacle at runtime. It does not prove successful V3 persistence.
Independent Superpowers review found no issues in this rejection evidence.
Combined PostgreSQL18 races, including historical V1/V2 successful completion,
exited0 in17.470s. A fresh standalone UI build also exited0.

## Successful local V3 finalization

The unpublished schema50 legacy enqueue now skips projection V3 as well as V2.
Its V1-only table guard remains intact, including for cached predecessor code.
Actual PostgreSQL measured the new live fingerprint:
`f124ddec35f3c93c4dc9b9426b38adee49f1edc52abc1dda6e2ce61305c525be`.
The down migration removes the exact revised filter; its first rollback test
caught the old removal needle, which was corrected before verification.

The codec-valid V3 receipt now commits and replays successfully under the
test-only coordinator grant: three session rows, one projection receipt, one
sandbox search entry and no legacy entry. Persisted sandbox/source fields match
the projection, and a stale legacy insert is rejected. Invalid item cases still
roll back all effects. Actual PostgreSQL races for precise and V1/V2 queue
behavior passed18.211s; precise plus rollback/reinstall passed13.831s.
Independent Superpowers review found no issues in the enqueue change.

At this earlier checkpoint, registration and repository/startup routing were
still missing. They now exist under registered51; see the current reconciliation
in `2026-09-11-process-precision-finalization-plan.md`. The test-only-grant result
above remains local database evidence, not production activation or live search.
